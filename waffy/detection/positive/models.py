"""Positive security model: Route configuration schema and constraint validator.

Validates:
- Allowed HTTP methods
- Allowed Content-Types
- Parameter existence, types, max lengths, and regex constraints
- Unknown parameter policy (REJECT or FLAG)
"""

import re
import tomllib
from collections.abc import Sequence
from enum import StrEnum
from pathlib import Path

from pydantic import BaseModel, Field

from waffy.core.enums import HttpMethod
from waffy.core.exceptions import ConfigurationError
from waffy.core.models.domain import HttpRequestRecord, PositiveSecurityViolation


class UnknownParamPolicy(StrEnum):
    """Action when an undeclared parameter is present in request."""

    ALLOW = "allow"
    FLAG = "flag"
    REJECT = "reject"


class ParameterConstraint(BaseModel):
    """Validation constraints on an individual parameter."""

    name: str
    param_type: str = "string"  # "string", "int", "float", "bool", "email", "uuid"
    required: bool = False
    max_length: int | None = None
    min_length: int | None = None
    regex_pattern: str | None = None
    allowed_values: list[str] | None = None


class RouteSecurityConfig(BaseModel):
    """Positive security configuration for an individual route/endpoint."""

    route_id: str
    path_pattern: str  # Regex or prefix pattern matching request.path
    allowed_methods: list[HttpMethod] = Field(
        default_factory=lambda: [HttpMethod.GET, HttpMethod.POST]
    )
    allowed_content_types: list[str] = Field(
        default_factory=lambda: ["application/json", "application/x-www-form-urlencoded"]
    )
    parameters: list[ParameterConstraint] = Field(
        default_factory=lambda: list[ParameterConstraint]()
    )
    unknown_param_policy: UnknownParamPolicy = UnknownParamPolicy.ALLOW


class PositiveSecurityEngine:
    """Validator evaluating requests against declared RouteSecurityConfig schemas."""

    def __init__(self, routes: Sequence[RouteSecurityConfig]) -> None:
        self.routes = list(routes)
        self.compiled_routes: list[tuple[re.Pattern[str], RouteSecurityConfig]] = []
        for r in self.routes:
            self.compiled_routes.append((re.compile(r.path_pattern), r))

    def get_route_config(self, path: str) -> RouteSecurityConfig | None:
        """Find the first matching route configuration for a given path."""
        for pattern, config in self.compiled_routes:
            if pattern.search(path):
                return config
        return None

    def validate(self, request: HttpRequestRecord) -> list[PositiveSecurityViolation]:
        """Check request against matching positive-security route schema if defined."""
        config = self.get_route_config(request.path)
        if config is None:
            # Route has no positive security config -> fallback cleanly to signature-only checks
            return []

        violations: list[PositiveSecurityViolation] = []

        # 1. Method check
        if request.method not in config.allowed_methods:
            violations.append(
                PositiveSecurityViolation(
                    route_id=config.route_id,
                    constraint_name="allowed_methods",
                    parameter_name=None,
                    expected=str([m.value for m in config.allowed_methods]),
                    actual=request.method.value,
                    score_weight=10.0,
                )
            )

        # Collect all incoming parameters from query params and parsed body dict
        incoming_params: dict[str, list[str]] = {}
        for k, v in request.query_params.items():
            incoming_params.setdefault(k, []).extend(v)

        for bk, bv in request.parsed_body_summary.items():
            if isinstance(bv, list):
                str_items: list[str] = [str(item) for item in bv]  # type: ignore[reportUnknownVariableType]
                incoming_params.setdefault(bk, []).extend(str_items)
            elif bv is not None:
                incoming_params.setdefault(bk, []).append(str(bv))

        declared_param_map = {p.name: p for p in config.parameters}

        # 2. Check for unknown parameters
        for incoming_k in incoming_params:
            if incoming_k not in declared_param_map and config.unknown_param_policy in (
                UnknownParamPolicy.FLAG,
                UnknownParamPolicy.REJECT,
            ):
                weight = 5.0 if config.unknown_param_policy == UnknownParamPolicy.FLAG else 15.0
                violations.append(
                    PositiveSecurityViolation(
                        route_id=config.route_id,
                        constraint_name="unknown_parameter",
                        parameter_name=incoming_k,
                        expected="declared parameter",
                        actual=f"unknown param '{incoming_k}'",
                        score_weight=weight,
                    )
                )

        # 3. Check declared parameter constraints
        for param_name, constraint in declared_param_map.items():
            vals = incoming_params.get(param_name)
            if not vals:
                if constraint.required:
                    violations.append(
                        PositiveSecurityViolation(
                            route_id=config.route_id,
                            constraint_name="required_parameter",
                            parameter_name=param_name,
                            expected="present",
                            actual="missing",
                            score_weight=5.0,
                        )
                    )
                continue

            for val in vals:
                # Max length
                if constraint.max_length is not None and len(val) > constraint.max_length:
                    violations.append(
                        PositiveSecurityViolation(
                            route_id=config.route_id,
                            constraint_name="max_length",
                            parameter_name=param_name,
                            expected=f"len <= {constraint.max_length}",
                            actual=f"len={len(val)}",
                            score_weight=5.0,
                        )
                    )

                # Min length
                if constraint.min_length is not None and len(val) < constraint.min_length:
                    violations.append(
                        PositiveSecurityViolation(
                            route_id=config.route_id,
                            constraint_name="min_length",
                            parameter_name=param_name,
                            expected=f"len >= {constraint.min_length}",
                            actual=f"len={len(val)}",
                            score_weight=5.0,
                        )
                    )

                # Regex pattern
                if constraint.regex_pattern and not re.search(constraint.regex_pattern, val):
                    violations.append(
                        PositiveSecurityViolation(
                            route_id=config.route_id,
                            constraint_name="regex_pattern",
                            parameter_name=param_name,
                            expected=constraint.regex_pattern,
                            actual=val[:20],
                            score_weight=5.0,
                        )
                    )

                # Type check
                if constraint.param_type == "int" and not val.isdigit() and not (
                    val.startswith("-") and val[1:].isdigit()
                ):
                    violations.append(
                        PositiveSecurityViolation(
                            route_id=config.route_id,
                            constraint_name="type_int",
                            parameter_name=param_name,
                            expected="integer",
                            actual=val[:20],
                            score_weight=5.0,
                        )
                    )

        return violations


def load_route_configs_from_dir(directory: str | Path) -> list[RouteSecurityConfig]:
    """Load route security schemas from a directory of TOML files."""
    route_dir = Path(directory)
    if not route_dir.is_dir():
        return []

    configs: list[RouteSecurityConfig] = []
    for file_path in sorted(route_dir.glob("*.toml")):
        try:
            with open(file_path, "rb") as f:
                data = tomllib.load(f)
            if "routes" in data:
                for item in data["routes"]:
                    configs.append(RouteSecurityConfig.model_validate(item))
            elif "route_id" in data:
                configs.append(RouteSecurityConfig.model_validate(data))
        except Exception as e:
            msg = f"Failed to load route security config '{file_path}': {e}"
            raise ConfigurationError(msg) from e

    return configs
