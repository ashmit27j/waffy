"""Signature and rule definition schema and TOML loader."""

import tomllib
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from waffy.core.enums import ParanoiaLevel, SignatureCategory, TargetField
from waffy.core.exceptions import RuleLoadError


class SignatureDefinition(BaseModel):
    """Signature configuration model loaded from rule TOML files."""

    id: str
    category: SignatureCategory
    pattern: str
    paranoia_level: ParanoiaLevel = ParanoiaLevel.PL1
    target_fields: list[TargetField] = Field(
        default_factory=lambda: [TargetField.PATH, TargetField.QUERY_PARAMS]
    )
    # Optional: when set, `pattern` is only evaluated against a target item
    # whose field/parameter *name* also matches this regex (e.g. a
    # parameter-name heuristic like "url"/"webhook"/"redirect" combined with
    # a value that looks like an absolute URL) -- lets a signature combine a
    # weak name signal with a value signal instead of matching on either
    # alone. `None` (default) preserves every existing signature's
    # value-only matching behavior unchanged.
    field_name_pattern: str | None = None
    score_weight: float = Field(default=5.0, ge=0.0)
    description: str = ""
    references: list[str] = Field(default_factory=lambda: list[str]())
    enabled: bool = True


class RuleFileSchema(BaseModel):
    """Container schema for TOML files with a list of rules."""

    rules: list[SignatureDefinition] = Field(default_factory=lambda: list[SignatureDefinition]())


def load_rules_from_file(path: str | Path) -> list[SignatureDefinition]:
    """Load and validate signatures from a single TOML file.

    Raises:
        RuleLoadError: If file cannot be read, contains malformed TOML, or fails schema validation.
    """
    rule_path = Path(path)
    if not rule_path.is_file():
        raise RuleLoadError(f"Rule file not found at: {rule_path}")

    try:
        with open(rule_path, "rb") as f:
            data: dict[str, Any] = tomllib.load(f)
    except Exception as e:
        raise RuleLoadError(f"Malformed TOML in rule file '{rule_path}': {e}") from e

    try:
        container = RuleFileSchema.model_validate(data)
        return container.rules
    except Exception as e:
        raise RuleLoadError(f"Invalid rule schema in '{rule_path}': {e}") from e


def load_all_rules_from_dir(directory: str | Path) -> list[SignatureDefinition]:
    """Scan directory for .toml rule files, load all signatures, and check for duplicates.

    Raises:
        RuleLoadError: If duplicate rule IDs are discovered across files or files are invalid.
    """
    rule_dir = Path(directory)
    if not rule_dir.is_dir():
        return []

    rules: list[SignatureDefinition] = []
    seen_ids: dict[str, Path] = {}

    for file_path in sorted(rule_dir.glob("*.toml")):
        file_rules = load_rules_from_file(file_path)
        for r in file_rules:
            if r.id in seen_ids:
                msg = (
                    f"Duplicate rule ID '{r.id}' found in '{file_path}' "
                    f"(already in '{seen_ids[r.id]}')"
                )
                raise RuleLoadError(msg)
            seen_ids[r.id] = file_path
            rules.append(r)

    return rules
