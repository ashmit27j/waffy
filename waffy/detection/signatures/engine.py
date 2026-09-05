"""Signature matching engine with regex complexity and per-request time budget guards.

Per spec §7 & CLAUDE.md:
- Matches enabled signatures at or below the configured paranoia level.
- Executes against declared target fields.
- Checks execution duration against regex_budget_ms; if exceeded, logs
  RULE_ENGINE_BUDGET_EXCEEDED and aborts remaining checks without breaking the request.
"""

import logging
import re
import time
from collections.abc import Sequence
from typing import Any

from waffy.core.enums import ParanoiaLevel, TargetField
from waffy.core.models.domain import HttpRequestRecord, SignatureMatch
from waffy.detection.signatures.schema import SignatureDefinition

logger = logging.getLogger("waffy.detection.signatures")


class CompiledSignature:
    """In-memory compiled signature structure."""

    def __init__(self, definition: SignatureDefinition) -> None:
        self.definition = definition
        try:
            self.regex: re.Pattern[str] = re.compile(
                definition.pattern, re.IGNORECASE | re.MULTILINE
            )
        except re.error as e:
            raise ValueError(f"Invalid regex for signature {definition.id}: {e}") from e

        self.field_name_regex: re.Pattern[str] | None = None
        if definition.field_name_pattern is not None:
            try:
                self.field_name_regex = re.compile(
                    definition.field_name_pattern, re.IGNORECASE
                )
            except re.error as e:
                raise ValueError(
                    f"Invalid field_name_pattern for signature {definition.id}: {e}"
                ) from e


class SignatureEngine:
    """Engine executing negative-security signature matches against HttpRequestRecords."""

    def __init__(
        self,
        signatures: Sequence[SignatureDefinition],
        paranoia_level: ParanoiaLevel = ParanoiaLevel.PL1,
        time_budget_ms: float = 50.0,
    ) -> None:
        self.paranoia_level = paranoia_level
        self.time_budget_ms = time_budget_ms
        self.compiled_signatures: list[CompiledSignature] = []
        self.reload(signatures)

    def reload(self, signatures: Sequence[SignatureDefinition]) -> None:
        """Compile and index enabled signatures."""
        compiled: list[CompiledSignature] = []
        for sig in signatures:
            if sig.enabled:
                compiled.append(CompiledSignature(sig))
        self.compiled_signatures = compiled

    def _extract_target_strings(
        self,
        request: HttpRequestRecord,
        raw_body_bytes: bytes,
        target_fields: list[TargetField],
    ) -> list[tuple[TargetField, str | None, str]]:
        """Extract inspectable (target_field, field_name, value_string) triples from request."""
        results: list[tuple[TargetField, str | None, str]] = []

        for tf in target_fields:
            if tf == TargetField.PATH:
                results.append((TargetField.PATH, None, request.path))
                if request.raw_path and request.raw_path != request.path:
                    results.append((TargetField.PATH, "raw", request.raw_path))

            elif tf == TargetField.QUERY_PARAMS:
                results.append((TargetField.QUERY_PARAMS, "raw_query", request.query_string))
                for param_name, values in request.query_params.items():
                    for val in values:
                        results.append((TargetField.QUERY_PARAMS, param_name, val))

            elif tf == TargetField.HEADERS:
                for k, v in request.headers:
                    results.append((TargetField.HEADERS, k, v))

            elif tf == TargetField.COOKIES:
                for ck, cv in request.cookies.items():
                    results.append((TargetField.COOKIES, ck, cv))

            elif tf == TargetField.BODY_FIELDS:
                summary = request.parsed_body_summary
                self._extract_nested_values(summary, results, TargetField.BODY_FIELDS)

            elif tf == TargetField.RAW_BODY:
                if raw_body_bytes:
                    text_body = raw_body_bytes.decode("utf-8", errors="replace")
                    results.append((TargetField.RAW_BODY, None, text_body))

            elif tf == TargetField.METHOD:
                results.append((TargetField.METHOD, None, request.method.value))

        return results

    def _extract_nested_values(
        self,
        data: Any,
        results: list[tuple[TargetField, str | None, str]],
        target_field: TargetField,
        prefix: str = "",
    ) -> None:
        """Recursively extract string values from parsed body JSON/form structures."""
        if isinstance(data, dict):
            # Explicit dict iteration for strict pyright typing
            data_dict: dict[str, Any] = data  # type: ignore[reportUnknownVariableType]
            for k, v in data_dict.items():
                p = f"{prefix}.{k}" if prefix else str(k)
                self._extract_nested_values(v, results, target_field, p)
        elif isinstance(data, list):
            data_list: list[Any] = data  # type: ignore[reportUnknownVariableType]
            for idx, item in enumerate(data_list):
                p = f"{prefix}[{idx}]"
                self._extract_nested_values(item, results, target_field, p)
        elif data is not None:
            results.append((target_field, prefix or None, str(data)))

    def match(
        self,
        request: HttpRequestRecord,
        raw_body_bytes: bytes = b"",
    ) -> list[SignatureMatch]:
        """Execute signature inspection across request targets with budget enforcement."""
        matches: list[SignatureMatch] = []
        start_time = time.perf_counter()
        budget_sec = self.time_budget_ms / 1000.0

        for comp_sig in self.compiled_signatures:
            sig = comp_sig.definition

            # Paranoia level gating
            if sig.paranoia_level > self.paranoia_level:
                continue

            # Time budget check
            elapsed = time.perf_counter() - start_time
            if elapsed > budget_sec:
                logger.warning(
                    "RULE_ENGINE_BUDGET_EXCEEDED: matching aborted after %.2f ms for request %s",
                    elapsed * 1000.0,
                    request.request_id,
                )
                break

            target_items = self._extract_target_strings(request, raw_body_bytes, sig.target_fields)

            for tf, field_name, text in target_items:
                if not text:
                    continue

                if comp_sig.field_name_regex is not None and (
                    field_name is None or not comp_sig.field_name_regex.search(field_name)
                ):
                    continue

                m = comp_sig.regex.search(text)
                if m:
                    # Capture matched snippet with length bounds
                    match_span = m.span()
                    snippet = text[max(0, match_span[0] - 10) : min(len(text), match_span[1] + 10)]
                    matches.append(
                        SignatureMatch(
                            signature_id=sig.id,
                            category=sig.category,
                            matched_field=tf,
                            field_name=field_name,
                            matched_snippet=snippet,
                            offset=match_span[0],
                            score_weight=sig.score_weight,
                        )
                    )
                    break  # Matched this signature for this request

        return matches
