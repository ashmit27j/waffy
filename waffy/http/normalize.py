"""Anti-evasion normalization pipeline per spec §5.

Ordered pipeline:
1. Multi-pass percent-decoding with recursion cap.
2. '+' to space conversion in query parameters.
3. Unicode NFKC normalization.
4. Path traversal normalization (collapsing duplicate slashes, './', '../').
5. Case normalization for case-insensitive matching.
"""

import unicodedata
from collections.abc import Sequence
from urllib.parse import unquote


def normalize_percent_encoding(text: str, max_passes: int = 5) -> tuple[str, int]:
    """Decode percent-encoded text iteratively up to max_passes.

    Returns:
        tuple[str, int]: (normalized_text, pass_count)
    """
    current = text
    passes = 0

    while passes < max_passes:
        # Check if there is percent encoding to decode
        if "%" not in current:
            break
        decoded = unquote(current)
        passes += 1
        if decoded == current:
            break
        current = decoded

    return current, max(1, passes)


def normalize_query_string(query: str, max_passes: int = 5) -> tuple[str, int]:
    """Normalize query string handling '+' as space and percent decoding."""
    # Replace '+' with space first or decode
    decoded_percent, passes = normalize_percent_encoding(query, max_passes=max_passes)
    # Unify spaces
    decoded_plus = decoded_percent.replace("+", " ")
    # Unicode NFKC normalization
    nfkc = unicodedata.normalize("NFKC", decoded_plus)
    # Null-byte stripping for detection safety
    cleaned = nfkc.replace("\x00", "")
    return cleaned, passes


def normalize_path_for_detection(path: str, max_passes: int = 5) -> tuple[str, int]:
    """Normalize URL path for traversal and evasion detection without mutating routed path.

    Collapses duplicate slashes, '.', '..', and decodes percent-encoded characters like %2e%2e%2f.
    """
    decoded, passes = normalize_percent_encoding(path, max_passes=max_passes)
    # NFKC
    nfkc = unicodedata.normalize("NFKC", decoded)
    # Null-byte removal
    cleaned = nfkc.replace("\x00", "")

    # Replace backslashes with forward slashes for cross-platform detection
    cleaned = cleaned.replace("\\", "/")

    # Split into segments and collapse
    segments = cleaned.split("/")
    resolved_segments: list[str] = []

    for seg in segments:
        if seg in ("", "."):
            continue
        if seg == "..":
            if resolved_segments:
                resolved_segments.pop()
        else:
            resolved_segments.append(seg)

    normalized_path = "/" + "/".join(resolved_segments)
    if path.endswith("/") and normalized_path != "/":
        normalized_path += "/"

    return normalized_path, passes


def normalize_text_nfkc(text: str, max_passes: int = 5) -> tuple[str, int]:
    """General text normalization for headers, body fields, and cookies."""
    decoded, passes = normalize_percent_encoding(text, max_passes=max_passes)
    nfkc = unicodedata.normalize("NFKC", decoded)
    cleaned = nfkc.replace("\x00", "")
    return cleaned, passes


def normalize_headers_for_detection(
    headers: Sequence[tuple[str, str]],
) -> list[tuple[str, str]]:
    """Normalize header keys (lowercase) and values for signature inspection."""
    normalized: list[tuple[str, str]] = []
    for k, v in headers:
        key_lower = k.strip().lower()
        val_norm, _ = normalize_text_nfkc(v.strip())
        normalized.append((key_lower, val_norm))
    return normalized
