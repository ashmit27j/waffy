"""Canonical feature extraction for waffy ML anomaly scoring per spec §11.

Single implementation rule:
Both offline baseline-building and runtime scoring MUST call this exact module.

Feature Schema: Version 1 (12 numerical features)
"""

import math
from typing import Final

from pydantic import BaseModel, Field

from waffy.core.models.domain import HttpRequestRecord

FEATURE_SCHEMA_VERSION: Final[str] = "v1"

FEATURE_NAMES: list[str] = [
    "request_total_length",
    "param_count",
    "param_length_max",
    "param_entropy_max",
    "path_depth",
    "path_length",
    "header_count",
    "unusual_headers_flag",
    "char_ratio_special",
    "char_ratio_digits",
    "char_ratio_alnum",
    "encoding_layers",
]


def calculate_shannon_entropy(text: str) -> float:
    """Compute Shannon entropy (bits per symbol) for an input string."""
    if not text:
        return 0.0
    length = len(text)
    freqs: dict[str, int] = {}
    for char in text:
        freqs[char] = freqs.get(char, 0) + 1

    entropy = 0.0
    for count in freqs.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


class RequestFeatureVector(BaseModel):
    """Pydantic model representing the typed, versioned numerical feature vector."""

    schema_version: str = FEATURE_SCHEMA_VERSION
    features: list[float] = Field(default_factory=lambda: list[float]())

    def to_array(self) -> list[float]:
        return self.features


def extract_features(
    request: HttpRequestRecord,
    raw_body_bytes: bytes = b"",
) -> RequestFeatureVector:
    """Extract canonical numerical features from an HttpRequestRecord."""
    # 1. Total request length (path + query + raw body size)
    total_len = float(len(request.path) + len(request.query_string) + len(raw_body_bytes))

    # 2. Parameter count & per-parameter metrics
    param_count = float(len(request.query_params))
    param_lens: list[int] = []
    param_entropies: list[float] = []

    for k, vals in request.query_params.items():
        for v in vals:
            full_val = f"{k}={v}"
            param_lens.append(len(full_val))
            param_entropies.append(calculate_shannon_entropy(full_val))

    for bk, bv in request.parsed_body_summary.items():
        str_v = str(bv)
        full_bval = f"{bk}={str_v}"
        param_lens.append(len(full_bval))
        param_entropies.append(calculate_shannon_entropy(str_v))
        param_count += 1.0

    max_param_len = float(max(param_lens)) if param_lens else 0.0
    max_param_entropy = float(max(param_entropies)) if param_entropies else 0.0

    # 3. Path metrics
    path_depth = float(len([seg for seg in request.path.split("/") if seg]))
    path_len = float(len(request.path))

    # 4. Header metrics
    header_count = float(len(request.headers))
    standard_headers = {
        "host",
        "user-agent",
        "accept",
        "accept-language",
        "accept-encoding",
        "connection",
        "content-type",
        "content-length",
        "cookie",
        "referer",
        "authorization",
        "cache-control",
        "upgrade-insecure-requests",
        "sec-fetch-dest",
        "sec-fetch-mode",
        "sec-fetch-site",
        "sec-fetch-user",
    }
    unusual_headers = 0
    for hk, _ in request.headers:
        if hk.lower() not in standard_headers:
            unusual_headers += 1
    unusual_headers_flag = 1.0 if unusual_headers > 0 else 0.0

    # 5. Character class ratios across query + path + body
    full_sample = request.path + request.query_string
    if raw_body_bytes:
        full_sample += raw_body_bytes.decode("utf-8", errors="replace")

    sample_len = max(1, len(full_sample))
    digits = sum(1 for c in full_sample if c.isdigit())
    alnum = sum(1 for c in full_sample if c.isalnum())
    special = sum(1 for c in full_sample if not c.isalnum() and not c.isspace())

    ratio_digits = float(digits) / sample_len
    ratio_alnum = float(alnum) / sample_len
    ratio_special = float(special) / sample_len

    # 6. Encoding layers from normalizer
    encoding_layers = float(request.encoding_layers)

    vector_values = [
        total_len,
        param_count,
        max_param_len,
        max_param_entropy,
        path_depth,
        path_len,
        header_count,
        unusual_headers_flag,
        ratio_special,
        ratio_digits,
        ratio_alnum,
        encoding_layers,
    ]

    return RequestFeatureVector(
        schema_version=FEATURE_SCHEMA_VERSION,
        features=vector_values,
    )
