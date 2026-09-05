"""Unit and integration tests for Phase 2 HTTP engine, parser, body, and normalization."""

import contextlib
import gzip
import importlib.util
import json
from collections.abc import Awaitable, Callable
from typing import Any

import httpx
import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st
from starlette.requests import Request

from tests.helpers.fakes import FakeUpstreamClient
from waffy.config.models import HttpConfig, WaffyConfig
from waffy.core.enums import HttpMethod
from waffy.core.exceptions import RequestMalformedError
from waffy.http.body import decompress_body, parse_body, parse_multipart_metadata, parse_safe_xml
from waffy.http.normalize import (
    normalize_path_for_detection,
    normalize_percent_encoding,
    normalize_query_string,
    normalize_text_nfkc,
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


# ---------------------------------------------------------------------------
# Property-based (Hypothesis) fuzz coverage for HTTP parsing & normalization
# (Step B2)
#
# Every function fuzzed here handles 100% attacker-controlled input, per
# CLAUDE.md. Table-driven tests above cover known evasion techniques; these
# properties instead assert invariants that must hold for ANY input, so
# Hypothesis can search for edge cases the table-driven tests don't
# anticipate. dev-only dependency -- see docs/ARCHITECTURE.md's dependency
# decisions section for the justification; hypothesis never ships in the
# runtime dependency set (it's under [project.optional-dependencies].dev).
#
# Properties asserted:
# 1. Normalization never crashes or hangs (bounded max_passes, bounded
#    per-example wall-clock via Hypothesis's `deadline`).
# 2. Normalization is idempotent once it has converged (stopped before
#    hitting max_passes) -- re-running it on its own output is a no-op.
# 3. The parser (validate_request_framing) and body layer (parse_body) never
#    raise anything other than the documented RequestMalformedError -- they
#    parse, or they raise that one typed exception, never an unhandled one.
# 4. Decoding never produces output larger than the documented
#    max_decompressed_body_bytes bound (the decompression-bomb guard).
# ---------------------------------------------------------------------------


@given(text=st.text(max_size=500), max_passes=st.integers(min_value=1, max_value=10))
@settings(max_examples=200, deadline=1000, suppress_health_check=[HealthCheck.too_slow])
def test_property_normalize_percent_encoding_never_crashes_and_bounded(
    text: str, max_passes: int
) -> None:
    result, passes = normalize_percent_encoding(text, max_passes=max_passes)
    assert isinstance(result, str)
    assert 1 <= passes <= max_passes


# Biased alphabet mixing percent-encoding syntax, hex digits, and control
# characters -- more likely than plain st.text() to hit multi-pass decode
# edge cases and null-byte/backslash interactions.
_evasion_alphabet = st.sampled_from("%0123456789abcdefABCDEF./\\.. \x00\t\r\n<>'\";")


@given(
    text=st.text(alphabet=_evasion_alphabet, max_size=300),
    max_passes=st.integers(min_value=1, max_value=8),
)
@settings(max_examples=300, deadline=1000, suppress_health_check=[HealthCheck.too_slow])
def test_property_normalize_percent_encoding_idempotent_once_converged(
    text: str, max_passes: int
) -> None:
    result, passes = normalize_percent_encoding(text, max_passes=max_passes)
    if passes < max_passes:
        # Loop exited via one of its own break conditions (no more '%', or a
        # decode pass was a no-op) rather than hitting the cap -- re-running
        # on the already-converged output must change nothing further.
        result2, _ = normalize_percent_encoding(result, max_passes=max_passes)
        assert result2 == result


@given(text=st.text(max_size=300))
@settings(max_examples=200, deadline=1000, suppress_health_check=[HealthCheck.too_slow])
def test_property_normalize_query_string_never_crashes(text: str) -> None:
    result, passes = normalize_query_string(text, max_passes=5)
    assert isinstance(result, str)
    assert "\x00" not in result
    assert passes >= 1


@given(text=st.text(max_size=300))
@settings(max_examples=200, deadline=1000, suppress_health_check=[HealthCheck.too_slow])
def test_property_normalize_path_for_detection_never_crashes(text: str) -> None:
    result, passes = normalize_path_for_detection(text, max_passes=5)
    assert isinstance(result, str)
    assert "\x00" not in result
    assert passes >= 1
    assert result.startswith("/")


@given(text=st.text(max_size=300))
@settings(max_examples=200, deadline=1000, suppress_health_check=[HealthCheck.too_slow])
def test_property_normalize_text_nfkc_never_crashes(text: str) -> None:
    result, passes = normalize_text_nfkc(text, max_passes=5)
    assert isinstance(result, str)
    assert "\x00" not in result
    assert passes >= 1


@given(
    headers=st.lists(
        st.tuples(
            st.binary(max_size=40).filter(lambda b: b"\n" not in b and b"\r" not in b),
            st.binary(max_size=200).filter(lambda b: b"\n" not in b and b"\r" not in b),
        ),
        max_size=30,
    )
)
@settings(max_examples=200, deadline=1000, suppress_health_check=[HealthCheck.too_slow])
def test_property_validate_request_framing_never_raises_unexpected_exception(
    headers: list[tuple[bytes, bytes]],
) -> None:
    """Either parses cleanly or raises the one documented RequestMalformedError
    -- any other exception type propagating out of this test is the failure.
    """
    cfg = HttpConfig()
    with contextlib.suppress(RequestMalformedError):
        validate_request_framing(headers, cfg)


def test_hypothesis_found_bug_multipart_content_type_with_crlf_no_longer_crashes() -> None:
    """Regression test for a real bug Hypothesis found during Step B2:
    parse_multipart_metadata() raised an unhandled `ValueError` (not the
    documented RequestMalformedError) for a Content-Type header containing
    a bare CR/LF, e.g. content_type='\\r0'. Root cause: the function built an
    `email.message.EmailMessage()` purely to assign `msg["Content-Type"]`
    for header validation, then never read `msg` again anywhere -- the
    boundary marker was (and still is) parsed independently via
    `content_type_header.split(";")`. That EmailMessage construction was
    dead code, and it was also the only thing in this function that could
    raise a non-RequestMalformedError exception. Fixed by deleting the
    unused EmailMessage entirely (waffy/http/body.py) rather than adding a
    try/except around code that had no purpose.
    """
    result = parse_multipart_metadata(b"", "\r0")
    assert result == {"raw_parts": 0}

    result2 = parse_multipart_metadata(b"data", "multipart/form-data\r\nboundary=x")
    assert isinstance(result2, dict)


@given(body=st.binary(max_size=2000), content_type=st.text(max_size=100))
@settings(max_examples=200, deadline=1000, suppress_health_check=[HealthCheck.too_slow])
def test_property_parse_multipart_metadata_never_raises_unexpected_exception(
    body: bytes, content_type: str
) -> None:
    """Direct fuzz of parse_multipart_metadata() itself (not just through
    parse_body()'s generic exception wrapper) -- it's independently exported
    public API (waffy.http.__all__), so its own contract must hold: parse,
    or raise RequestMalformedError, never anything else.
    """
    try:
        result = parse_multipart_metadata(body, content_type)
    except RequestMalformedError:
        return
    assert isinstance(result, dict)


@given(
    body=st.binary(max_size=2000),
    content_type=st.one_of(
        st.sampled_from(
            [
                "application/json",
                "application/x-www-form-urlencoded",
                "multipart/form-data; boundary=X",
                "application/xml",
                "text/xml",
                "text/plain",
                "",
            ]
        ),
        st.text(max_size=40),
    ),
    content_encoding=st.one_of(
        st.sampled_from(["", "gzip", "deflate", "zlib", "identity", "br"]),
        st.text(max_size=20),
    ),
)
@settings(max_examples=300, deadline=1000, suppress_health_check=[HealthCheck.too_slow])
def test_property_parse_body_never_raises_unexpected_exception_and_respects_bound(
    body: bytes, content_type: str, content_encoding: str
) -> None:
    """parse_body() must either succeed (bytes + dict, within the
    configured decompressed-size bound) or raise RequestMalformedError --
    never any other exception, and never a silently oversized result.
    """
    cfg = HttpConfig()
    try:
        decompressed, summary = parse_body(body, content_type, content_encoding, cfg)
    except RequestMalformedError:
        return
    assert isinstance(decompressed, bytes)
    assert isinstance(summary, dict)
    assert len(decompressed) <= cfg.max_decompressed_body_bytes


@given(size_multiplier=st.integers(min_value=1, max_value=500))
@settings(max_examples=80, deadline=2000, suppress_health_check=[HealthCheck.too_slow])
def test_property_decompression_bomb_guard_never_exceeds_configured_bound(
    size_multiplier: int,
) -> None:
    """Tries to violate the decompression-bomb guard across a wide range of
    decompressed sizes -- for every size, the guard must either reject the
    payload outright or the actual decompressed output must stay within the
    configured bound. Never a silent, unbounded expansion.
    """
    cfg = HttpConfig(max_decompressed_body_bytes=10_000, max_decompression_ratio=5.0)
    raw = b"A" * (size_multiplier * 1000)  # up to ~500,000 decompressed bytes
    compressed = gzip.compress(raw)

    try:
        result = decompress_body(compressed, "gzip", cfg)
    except RequestMalformedError:
        return  # guard correctly rejected an oversized/high-ratio payload
    assert len(result) <= cfg.max_decompressed_body_bytes
