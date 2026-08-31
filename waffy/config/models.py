"""Pydantic v2 configuration settings models for waffy."""

import tomllib
from ipaddress import IPv4Network, IPv6Network
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field, field_validator

from waffy.core.enums import (
    EnforcementMode,
    FailureMode,
    ParanoiaLevel,
    SignatureCategory,
)
from waffy.core.exceptions import ConfigurationError


class TransportConfig(BaseModel):
    """Transport and listener configuration."""

    mode: Literal["standalone_tls", "plaintext", "embedded"] = "plaintext"
    host: str = "127.0.0.1"
    port: int = Field(default=8080, ge=1, le=65535)
    upstream_url: str = "http://127.0.0.1:8000"
    max_connections: int = Field(default=1000, ge=1)
    timeout_seconds: float = Field(default=30.0, gt=0.0)


class HttpConfig(BaseModel):
    """HTTP framing, size bounds, and decompression limits."""

    max_request_line_bytes: int = Field(default=8192, ge=128, le=65536)
    max_header_bytes: int = Field(default=65536, ge=1024, le=1048576)
    max_header_count: int = Field(default=100, ge=1, le=1000)
    max_body_bytes: int = Field(default=10485760, ge=0)
    max_decompressed_body_bytes: int = Field(default=20971520, ge=0)
    max_decompression_ratio: float = Field(default=10.0, ge=1.0)
    max_decode_passes: int = Field(default=5, ge=1, le=20)


class DetectionConfig(BaseModel):
    """Signature and positive security engine configuration."""

    paranoia_level: ParanoiaLevel = ParanoiaLevel.PL1
    enabled_categories: list[SignatureCategory] = Field(
        default_factory=lambda: [
            SignatureCategory.SQLI,
            SignatureCategory.XSS,
            SignatureCategory.COMMAND_INJECTION,
            SignatureCategory.PATH_TRAVERSAL,
            SignatureCategory.LFI_RFI,
            SignatureCategory.SSTI,
            SignatureCategory.XXE,
            SignatureCategory.DESERIALIZATION,
            SignatureCategory.CRLF_INJECTION,
            SignatureCategory.OPEN_REDIRECT,
            SignatureCategory.SCANNER_FINGERPRINT,
        ]
    )
    rules_dir: str = "config/rules"
    regex_budget_ms: float = Field(default=50.0, gt=0.0)


class AnomalyConfig(BaseModel):
    """ML anomaly detection configuration."""

    enabled: bool = True
    min_sample_size: int = Field(default=100, ge=10)
    model_dir: str = "config/models"
    anomaly_threshold: float = Field(default=0.75, ge=0.0, le=1.0)


class HttpLimitsConfig(BaseModel):
    """Inline transport limits configuration."""

    max_in_flight_requests: int = Field(default=1000, ge=1)
    max_concurrent_connections_per_ip: int = Field(default=50, ge=1)
    idle_timeout_seconds: float = Field(default=30.0, gt=0.0)


class RateLimitConfig(BaseModel):
    """Rate limiting and DoS threshold configuration."""

    enabled: bool = True
    requests_per_ip_per_minute: int = Field(default=120, ge=1)
    requests_per_session_per_minute: int = Field(default=300, ge=1)
    requests_per_route_per_minute: int = Field(default=600, ge=1)
    global_requests_per_minute: int = Field(default=10000, ge=1)
    window_seconds: int = Field(default=60, ge=1)


class BotDetectionConfig(BaseModel):
    """Bot and automation heuristic configuration."""

    enabled: bool = True
    honeypot_endpoints: list[str] = Field(
        default_factory=lambda: ["/.well-known/waffy-trap", "/admin/hidden-trap.php"]
    )
    scanner_weight: float = Field(default=25.0, ge=0.0)
    timing_regularity_threshold: float = Field(default=0.15, ge=0.0, le=1.0)


class CookieSecurityConfig(BaseModel):
    """Response-side cookie security attribute enforcement."""

    enabled: bool = True
    enforce_secure: bool = True
    enforce_httponly: bool = True
    samesite_policy: str = "Lax"


class CredentialStuffingConfig(BaseModel):
    """Failed login velocity threshold configuration."""

    enabled: bool = True
    max_failed_logins_per_ip: int = Field(default=10, ge=1)
    max_failed_logins_per_account: int = Field(default=5, ge=1)
    window_seconds: float = Field(default=60.0, gt=0.0)


class BotConfig(BaseModel):
    """Bot and automation heuristic configuration (alias for BotDetectionConfig)."""

    enabled: bool = True
    honeypot_path: str = "/.well-known/waffy-trap"
    scanner_weight: float = Field(default=25.0, ge=0.0)
    timing_regularity_threshold: float = Field(default=0.15, ge=0.0, le=1.0)


class EngineConfig(BaseModel):
    """Scoring weights and threat-level thresholds."""

    weight_signature_p1: float = Field(default=5.0, ge=0.0)
    weight_signature_p2: float = Field(default=10.0, ge=0.0)
    weight_signature_p3: float = Field(default=15.0, ge=0.0)
    weight_signature_p4: float = Field(default=20.0, ge=0.0)
    weight_positive_violation: float = Field(default=5.0, ge=0.0)
    weight_anomaly: float = Field(default=10.0, ge=0.0)
    weight_bot: float = Field(default=10.0, ge=0.0)
    weight_rate_limit: float = Field(default=15.0, ge=0.0)

    threshold_low: float = Field(default=5.0, ge=0.0)
    threshold_medium: float = Field(default=15.0, ge=0.0)
    threshold_high: float = Field(default=25.0, ge=0.0)
    threshold_critical: float = Field(default=40.0, ge=0.0)

    consecutive_escalation_count: int = Field(default=3, ge=1)


class EnforcementConfig(BaseModel):
    """Enforcement settings and fail-safe policy."""

    mode: EnforcementMode = EnforcementMode.SHADOW
    failure_mode: FailureMode = FailureMode.FAIL_OPEN
    block_status_code: int = Field(default=403, ge=400, le=599)
    max_bans_per_hour: int = Field(default=50, ge=1)
    default_ban_duration_seconds: int = Field(default=3600, ge=1)


class AllowlistConfig(BaseModel):
    """Static admin-defined IP allowlist."""

    ips: list[str] = Field(default_factory=lambda: ["127.0.0.1", "::1"])


class ApiConfig(BaseModel):
    """Management API & Control Panel settings."""

    host: str = "127.0.0.1"
    port: int = Field(default=9090, ge=1, le=65535)
    management_cidrs: list[str] = Field(default_factory=lambda: ["127.0.0.1/32", "::1/128"])
    api_token: str = "CHANGE_ME"
    ipc_socket_path: str = "/tmp/waffy_ipc.sock"

    @field_validator("management_cidrs")
    @classmethod
    def validate_cidrs(cls, v: list[str]) -> list[str]:
        for cidr in v:
            try:
                if "/" in cidr:
                    if "." in cidr:
                        _ = IPv4Network(cidr, strict=False)
                    else:
                        _ = IPv6Network(cidr, strict=False)
                else:
                    is_v4 = "." in cidr
                    _ = IPv4Network(f"{cidr}/32") if is_v4 else IPv6Network(f"{cidr}/128")
            except Exception as e:
                raise ValueError(f"Invalid management CIDR '{cidr}': {e}") from e
        return v


class IntegrationConfig(BaseModel):
    """SIEM and metrics exporter configuration."""

    siem_enabled: bool = False
    siem_host: str = "127.0.0.1"
    siem_port: int = Field(default=514, ge=1, le=65535)
    siem_protocol: Literal["udp", "tcp"] = "udp"
    metrics_enabled: bool = True
    metrics_port: int = Field(default=9100, ge=1, le=65535)


class LoggingConfig(BaseModel):
    """Logging and field redaction configuration."""

    redact_fields: list[str] = Field(
        default_factory=lambda: [
            "password",
            "passwd",
            "token",
            "secret",
            "authorization",
            "cookie",
            "set-cookie",
            "api_key",
            "apikey",
            "access_token",
            "refresh_token",
        ]
    )
    log_level: str = "INFO"


class WaffyConfig(BaseModel):
    """Root configuration model combining all subsystems."""

    transport: TransportConfig = Field(default_factory=TransportConfig)
    http: HttpConfig = Field(default_factory=HttpConfig)
    http_limits: HttpLimitsConfig = Field(default_factory=HttpLimitsConfig)
    detection: DetectionConfig = Field(default_factory=DetectionConfig)
    anomaly: AnomalyConfig = Field(default_factory=AnomalyConfig)
    rate_limiting: RateLimitConfig = Field(default_factory=RateLimitConfig)
    bot_detection: BotDetectionConfig = Field(default_factory=BotDetectionConfig)
    cookie_security: CookieSecurityConfig = Field(default_factory=CookieSecurityConfig)
    credential_stuffing: CredentialStuffingConfig = Field(
        default_factory=CredentialStuffingConfig
    )
    engine: EngineConfig = Field(default_factory=EngineConfig)
    enforcement: EnforcementConfig = Field(default_factory=EnforcementConfig)
    allowlist: AllowlistConfig = Field(default_factory=AllowlistConfig)
    api: ApiConfig = Field(default_factory=ApiConfig)
    integration: IntegrationConfig = Field(default_factory=IntegrationConfig)
    logging: LoggingConfig = Field(default_factory=LoggingConfig)


def load_config(path: str | Path | None = None) -> WaffyConfig:
    """Load and validate waffy configuration from TOML file or defaults.

    Defaults explicitly follow CLAUDE.md:
    - enforcement.mode is 'shadow'
    - enforcement.failure_mode is 'fail_open'

    Args:
        path: Optional file path to config TOML. If None, returns default configuration.

    Returns:
        Validated WaffyConfig instance.

    Raises:
        ConfigurationError: If file not found, invalid TOML syntax, or validation fails.
    """
    if path is None:
        return WaffyConfig()

    config_path = Path(path)
    if not config_path.is_file():
        raise ConfigurationError(f"Configuration file not found at: {config_path}")

    try:
        with open(config_path, "rb") as f:
            data = tomllib.load(f)
    except Exception as e:
        raise ConfigurationError(f"Malformed TOML in config file '{config_path}': {e}") from e

    try:
        return WaffyConfig.model_validate(data)
    except Exception as e:
        raise ConfigurationError(f"Invalid configuration in '{config_path}': {e}") from e
