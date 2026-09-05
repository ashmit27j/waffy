"""Content-Type aware request body parser and decompression with bomb protection."""

import gzip
import json
import xml.etree.ElementTree as ET
import zlib
from typing import Any
from urllib.parse import parse_qs

from waffy.config.models import HttpConfig
from waffy.core.exceptions import RequestMalformedError


def decompress_body(raw_bytes: bytes, encoding: str, config: HttpConfig) -> bytes:
    """Decompress request body with decompression-bomb guard.

    Guards against:
    1. Output size exceeding max_decompressed_body_bytes.
    2. Compression ratio exceeding max_decompression_ratio.
    """
    encoding = encoding.strip().lower()
    if not encoding or encoding in ("identity", "none"):
        return raw_bytes

    original_len = max(1, len(raw_bytes))

    try:
        if encoding == "gzip":
            decompressed = gzip.decompress(raw_bytes)
        elif encoding in ("deflate", "zlib"):
            decompressed = zlib.decompress(raw_bytes)
        else:
            raise RequestMalformedError(f"Unsupported Content-Encoding '{encoding}'")
    except RequestMalformedError:
        raise
    except Exception as e:
        raise RequestMalformedError(f"Corrupted or invalid compressed payload: {e}") from e

    decompressed_len = len(decompressed)
    if decompressed_len > config.max_decompressed_body_bytes:
        msg = (
            f"Decompressed body size {decompressed_len} bytes exceeds "
            f"max limit {config.max_decompressed_body_bytes}"
        )
        raise RequestMalformedError(msg)

    ratio = decompressed_len / original_len
    if ratio > config.max_decompression_ratio and decompressed_len > 1024:
        msg = (
            f"Decompression ratio {ratio:.2f} exceeds "
            f"max allowed ratio {config.max_decompression_ratio}"
        )
        raise RequestMalformedError(msg)

    return decompressed


def parse_safe_xml(xml_bytes: bytes) -> dict[str, Any]:
    """Parse XML payload with external entity resolution unconditionally disabled.

    Standard library xml.etree.ElementTree does not resolve external DTDs or entities by default,
    providing XXE safety at the parser level.
    """
    try:
        # Standard ElementTree parser is safe against XXE by default
        root = ET.fromstring(xml_bytes)
    except ET.ParseError as e:
        raise RequestMalformedError(f"Malformed XML payload: {e}") from e

    def elem_to_dict(elem: ET.Element) -> dict[str, Any]:
        d: dict[str, Any] = {"tag": elem.tag}
        if elem.attrib:
            d["attributes"] = elem.attrib
        if elem.text and elem.text.strip():
            d["text"] = elem.text.strip()
        children = [elem_to_dict(child) for child in elem]
        if children:
            d["children"] = children
        return d

    return elem_to_dict(root)


def parse_multipart_metadata(body: bytes, content_type_header: str) -> dict[str, Any]:
    """Extract metadata (field names, filenames, content-types, sizes) from multipart body."""
    # Simple multipart extraction
    boundary_marker = ""
    for param in content_type_header.split(";"):
        param = param.strip()
        if param.lower().startswith("boundary="):
            boundary_marker = param[9:].strip("\"'")
            break

    if not boundary_marker:
        return {"raw_parts": len(body)}

    boundary_bytes = ("--" + boundary_marker).encode("latin-1")
    parts = body.split(boundary_bytes)

    fields: dict[str, list[str]] = {}
    files: list[dict[str, Any]] = []

    for part in parts:
        part = part.strip()
        if not part or part == b"--":
            continue

        header_end = part.find(b"\r\n\r\n")
        if header_end == -1:
            header_end = part.find(b"\n\n")
            if header_end == -1:
                continue
            headers_raw = part[:header_end].decode("latin-1", errors="replace")
            part_body = part[header_end + 2:]
        else:
            headers_raw = part[:header_end].decode("latin-1", errors="replace")
            part_body = part[header_end + 4:]

        headers_dict: dict[str, str] = {}
        for line in headers_raw.splitlines():
            if ":" in line:
                hk, hv = line.split(":", 1)
                headers_dict[hk.strip().lower()] = hv.strip()

        disposition = headers_dict.get("content-disposition", "")
        if "filename=" in disposition:
            filename = ""
            for disp_param in disposition.split(";"):
                disp_param = disp_param.strip()
                if disp_param.startswith("filename="):
                    filename = disp_param[9:].strip("\"'")
                    break
            files.append(
                {
                    "filename": filename,
                    "content_type": headers_dict.get("content-type", "application/octet-stream"),
                    "size": len(part_body),
                }
            )
        elif "name=" in disposition:
            field_name = ""
            for disp_param in disposition.split(";"):
                disp_param = disp_param.strip()
                if disp_param.startswith("name="):
                    field_name = disp_param[5:].strip("\"'")
                    break
            if field_name:
                val = part_body.decode("utf-8", errors="replace").strip("\r\n")
                fields.setdefault(field_name, []).append(val)

    return {"fields": fields, "files": files}


def parse_body(
    body_bytes: bytes,
    content_type: str,
    content_encoding: str,
    config: HttpConfig,
) -> tuple[bytes, dict[str, Any]]:
    """Decompress and parse request body according to Content-Type.

    Returns:
        tuple[bytes, dict[str, Any]]: (decompressed_body, parsed_summary)
    """
    if not body_bytes:
        return b"", {}

    decompressed = decompress_body(body_bytes, content_encoding, config)
    ct_lower = content_type.lower().split(";")[0].strip()

    parsed_summary: dict[str, Any] = {}

    try:
        if ct_lower == "application/json":
            raw_json: Any = json.loads(decompressed.decode("utf-8", errors="replace"))
            if isinstance(raw_json, dict):
                parsed_summary = {str(k): v for k, v in raw_json.items()}  # type: ignore[reportUnknownVariableType]
            else:
                parsed_summary = {"_json_array_or_val": raw_json}
        elif ct_lower == "application/x-www-form-urlencoded":
            raw_qs = decompressed.decode("utf-8", errors="replace")
            parsed_summary = parse_qs(raw_qs, keep_blank_values=True)
        elif ct_lower.startswith("multipart/form-data"):
            parsed_summary = parse_multipart_metadata(decompressed, content_type)
        elif ct_lower in ("application/xml", "text/xml"):
            parsed_summary = parse_safe_xml(decompressed)
        else:
            parsed_summary = {"raw_size": len(decompressed)}
    except RequestMalformedError:
        raise
    except Exception as e:
        raise RequestMalformedError(f"Failed to parse body as {content_type}: {e}") from e

    return decompressed, parsed_summary
