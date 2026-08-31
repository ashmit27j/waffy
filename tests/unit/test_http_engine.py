"""Unit and integration tests for Phase 2 HTTP engine, parser, body, and normalization."""

import gzip
import json

import httpx
import pytest

from tests.helpers.fakes import FakeUpstreamClient
from waffy.config.models import HttpConfig, WaffyConfig
from waffy.core.exceptions import RequestMalformedError
from waffy.http.body import decompress_body, parse_body, parse_safe_xml
from waffy.http.normalize import (
    normalize_path_for_detection,
    normalize_percent_encoding,
    normalize_query_string,
)
from waffy.http.parser import validate_request_framing
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
