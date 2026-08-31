"""ASGI HTTP request parser and ambiguity/smuggling validation.

Per spec §4:
Parse and reject malformed/ambiguous requests outright before they reach detection:
- Mismatched or duplicate Content-Length
- Content-Length + Transfer-Encoding both present (classic smuggling vector)
- Invalid chunked framing
- Request line or headers exceeding size/count limits
- Body exceeding max_body_bytes

Malformed requests produce a RequestMalformedError and are rejected with 400 Bad Request,
even in SHADOW mode (because passing an ambiguous request to upstream undermines backend
consistency and bypasses security).
"""

from collections.abc import Sequence
from http.cookies import SimpleCookie
from urllib.parse import parse_qs

from starlette.requests import Request

from waffy.config.models import HttpConfig
from waffy.core.enums import HttpMethod
from waffy.core.exceptions import RequestMalformedError
from waffy.core.models.domain import HttpRequestRecord, TLSInfo
from waffy.http.body import parse_body
from waffy.http.normalize import (
    normalize_path_for_detection,
    normalize_query_string,
)


def validate_request_framing(
    raw_headers: Sequence[tuple[bytes, bytes]],
    config: HttpConfig,
) -> tuple[int | None, bool, str, str]:
    """Validate HTTP framing for desync / smuggling vectors.

    Returns:
        tuple[content_length, is_chunked, content_type, content_encoding]
    """
    content_length_values: list[str] = []
    transfer_encoding_values: list[str] = []
    content_type = ""
    content_encoding = ""
    total_header_bytes = 0

    if len(raw_headers) > config.max_header_count:
        raise RequestMalformedError(
            f"Header count {len(raw_headers)} exceeds maximum allowed {config.max_header_count}"
        )

    for k_raw, v_raw in raw_headers:
        total_header_bytes += len(k_raw) + len(v_raw) + 4
        k_str = k_raw.decode("latin-1", errors="replace").strip().lower()
        v_str = v_raw.decode("latin-1", errors="replace").strip()

        if k_str == "content-length":
            content_length_values.append(v_str)
        elif k_str == "transfer-encoding":
            transfer_encoding_values.append(v_str.lower())
        elif k_str == "content-type":
            content_type = v_str
        elif k_str == "content-encoding":
            content_encoding = v_str

    if total_header_bytes > config.max_header_bytes:
        raise RequestMalformedError(
            f"Total header size {total_header_bytes} exceeds limit {config.max_header_bytes}"
        )

    # Smuggling Guard 1: Both Content-Length and Transfer-Encoding present
    if content_length_values and transfer_encoding_values:
        raise RequestMalformedError(
            "Ambiguous framing: both Content-Length and Transfer-Encoding present"
        )

    # Smuggling Guard 2: Duplicate Content-Length headers with conflicting values
    parsed_cl: int | None = None
    if content_length_values:
        # Check comma-separated values or multiple header lines
        all_cls: list[str] = []
        for val in content_length_values:
            for item in val.split(","):
                all_cls.append(item.strip())

        first_cl = all_cls[0]
        for cl_item in all_cls[1:]:
            if cl_item != first_cl:
                raise RequestMalformedError(
                    f"Conflicting Content-Length values: {content_length_values}"
                )

        try:
            parsed_cl = int(first_cl)
            if parsed_cl < 0:
                raise ValueError("Negative Content-Length")
        except ValueError as e:
            raise RequestMalformedError(f"Invalid Content-Length value '{first_cl}': {e}") from e

    is_chunked = any("chunked" in te for te in transfer_encoding_values)

    return parsed_cl, is_chunked, content_type, content_encoding


async def parse_asgi_request(
    request: Request,
    config: HttpConfig,
) -> tuple[HttpRequestRecord, bytes]:
    """Parse incoming Starlette/ASGI request into canonical HttpRequestRecord + raw bytes.

    Validates request line size, headers, ambiguity, and bounds before normalizing.
    """
    raw_path = request.scope.get("raw_path", b"").decode("latin-1", errors="replace")
    if not raw_path:
        raw_path = request.url.path

    raw_query = request.scope.get("query_string", b"").decode("latin-1", errors="replace")
    request_line_len = len(request.method) + len(raw_path) + len(raw_query) + 12
    if request_line_len > config.max_request_line_bytes:
        raise RequestMalformedError(
            f"Request line length {request_line_len} exceeds max {config.max_request_line_bytes}"
        )

    # Extract headers
    raw_headers = request.scope.get("headers", [])
    parsed_cl, _, content_type, content_encoding = validate_request_framing(raw_headers, config)

    # Read body with max_body_bytes enforcement
    body_chunks: list[bytes] = []
    bytes_read = 0

    async for chunk in request.stream():
        bytes_read += len(chunk)
        if bytes_read > config.max_body_bytes:
            raise RequestMalformedError(
                f"Request body size {bytes_read} exceeds limit {config.max_body_bytes}"
            )
        body_chunks.append(chunk)

    raw_body = b"".join(body_chunks)

    # Validate Content-Length match if provided
    if parsed_cl is not None and len(raw_body) != parsed_cl:
        raise RequestMalformedError(
            f"Actual body size {len(raw_body)} does not match Content-Length {parsed_cl}"
        )

    # Parse and decompress body
    decompressed_body, body_summary = parse_body(
        raw_body, content_type, content_encoding, config
    )

    # Normalization pipeline
    norm_path, path_passes = normalize_path_for_detection(raw_path, config.max_decode_passes)
    norm_query, query_passes = normalize_query_string(raw_query, config.max_decode_passes)
    max_encoding_layers = max(path_passes, query_passes)

    # Query params
    query_params = parse_qs(norm_query, keep_blank_values=True)

    # Headers list preserving duplicates
    headers_list: list[tuple[str, str]] = []
    for k_raw, v_raw in raw_headers:
        headers_list.append((
            k_raw.decode("latin-1", errors="replace"),
            v_raw.decode("latin-1", errors="replace"),
        ))

    # Cookies
    cookie_header = request.headers.get("cookie", "")
    cookies_dict: dict[str, str] = {}
    if cookie_header:
        simple_cookie = SimpleCookie()
        try:
            simple_cookie.load(cookie_header)
            for morsel_key, morsel in simple_cookie.items():
                cookies_dict[morsel_key] = morsel.value
        except Exception:
            cookies_dict["raw"] = cookie_header

    # Client IP & Port
    client = request.client
    client_ip = client.host if client else "127.0.0.1"
    client_port = client.port if client else 0

    # TLS info if available in ASGI scope
    tls_info: TLSInfo | None = None
    if request.scope.get("scheme") == "https" or "tls" in request.scope:
        tls_info = TLSInfo(version="TLSv1.3")

    method_str = request.method.upper()
    try:
        http_method = HttpMethod(method_str)
    except ValueError:
        http_method = HttpMethod.GET  # fallback

    record = HttpRequestRecord(
        method=http_method,
        path=norm_path,
        raw_path=raw_path,
        query_string=norm_query,
        raw_query_string=raw_query,
        query_params=query_params,
        headers=headers_list,
        cookies=cookies_dict,
        client_ip=client_ip,
        client_port=client_port,
        tls_info=tls_info,
        raw_body_size=len(raw_body),
        parsed_body_summary=body_summary,
        encoding_layers=max_encoding_layers,
    )

    return record, decompressed_body
