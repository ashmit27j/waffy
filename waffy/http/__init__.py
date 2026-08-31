"""HTTP transport, parsing, body handling, and anti-evasion normalization."""

from waffy.http.body import decompress_body, parse_body, parse_multipart_metadata, parse_safe_xml
from waffy.http.normalize import (
    normalize_headers_for_detection,
    normalize_path_for_detection,
    normalize_percent_encoding,
    normalize_query_string,
    normalize_text_nfkc,
)
from waffy.http.parser import parse_asgi_request, validate_request_framing
from waffy.http.transport import ProxyApplication
from waffy.http.upstream import HttpxUpstreamClient

__all__ = [
    "HttpxUpstreamClient",
    "ProxyApplication",
    "decompress_body",
    "normalize_headers_for_detection",
    "normalize_path_for_detection",
    "normalize_percent_encoding",
    "normalize_query_string",
    "normalize_text_nfkc",
    "parse_asgi_request",
    "parse_body",
    "parse_multipart_metadata",
    "parse_safe_xml",
    "validate_request_framing",
]
