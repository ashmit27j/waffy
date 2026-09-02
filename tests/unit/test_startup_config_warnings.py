"""Tests for waffy/runtime/startup_checks.py (prompts/07): warnings for
security features enabled in config but not usably configured. Warnings
only -- must never raise, never change config, never block startup.
"""

import logging

import pytest

from waffy.config.models import WaffyConfig
from waffy.detection.session.services import CredentialStuffingDetector
from waffy.runtime.startup_checks import run_startup_config_warnings


def test_credential_stuffing_detector_is_configured_query() -> None:
    cfg = WaffyConfig()
    unconfigured = CredentialStuffingDetector(cfg.credential_stuffing)
    assert unconfigured.is_configured() is False

    cfg.credential_stuffing.login_failure_routes = ["/login"]
    configured = CredentialStuffingDetector(cfg.credential_stuffing)
    assert configured.is_configured() is True


def test_credential_stuffing_warning_triggered_when_routes_unconfigured(
    caplog: pytest.LogCaptureFixture,
) -> None:
    cfg = WaffyConfig()
    assert cfg.credential_stuffing.enabled is True
    assert cfg.credential_stuffing.login_failure_routes == []

    with caplog.at_level(logging.WARNING, logger="waffy.runtime.startup_checks"):
        warnings = run_startup_config_warnings(cfg)

    assert any("login_failure_routes" in w for w in warnings)
    assert any("login_failure_routes" in r.message for r in caplog.records)


def test_credential_stuffing_warning_not_triggered_when_configured(
    caplog: pytest.LogCaptureFixture,
) -> None:
    cfg = WaffyConfig()
    cfg.credential_stuffing.login_failure_routes = ["/login", "/api/v1/auth"]

    with caplog.at_level(logging.WARNING, logger="waffy.runtime.startup_checks"):
        warnings = run_startup_config_warnings(cfg)

    assert not any("login_failure_routes" in w for w in warnings)


def test_credential_stuffing_warning_not_triggered_when_feature_disabled(
    caplog: pytest.LogCaptureFixture,
) -> None:
    cfg = WaffyConfig()
    cfg.credential_stuffing.enabled = False
    assert cfg.credential_stuffing.login_failure_routes == []  # still unconfigured

    with caplog.at_level(logging.WARNING, logger="waffy.runtime.startup_checks"):
        warnings = run_startup_config_warnings(cfg)

    assert not any("login_failure_routes" in w for w in warnings)


def test_csrf_warning_triggered_in_embedded_mode_when_disabled(
    caplog: pytest.LogCaptureFixture,
) -> None:
    cfg = WaffyConfig()
    cfg.transport.mode = "embedded"
    assert cfg.csrf.enabled is False

    with caplog.at_level(logging.WARNING, logger="waffy.runtime.startup_checks"):
        warnings = run_startup_config_warnings(cfg)

    assert any("csrf" in w.lower() for w in warnings)


def test_csrf_warning_not_triggered_when_enabled(caplog: pytest.LogCaptureFixture) -> None:
    cfg = WaffyConfig()
    cfg.transport.mode = "embedded"
    cfg.csrf.enabled = True

    with caplog.at_level(logging.WARNING, logger="waffy.runtime.startup_checks"):
        warnings = run_startup_config_warnings(cfg)

    assert not any("csrf" in w.lower() for w in warnings)


def test_csrf_warning_not_triggered_outside_embedded_mode(
    caplog: pytest.LogCaptureFixture,
) -> None:
    cfg = WaffyConfig()
    cfg.transport.mode = "plaintext"
    assert cfg.csrf.enabled is False  # left off, but mode isn't embedded

    with caplog.at_level(logging.WARNING, logger="waffy.runtime.startup_checks"):
        warnings = run_startup_config_warnings(cfg)

    assert not any("csrf" in w.lower() for w in warnings)


def test_no_warnings_when_fully_configured() -> None:
    cfg = WaffyConfig()
    cfg.transport.mode = "embedded"
    cfg.csrf.enabled = True
    cfg.credential_stuffing.login_failure_routes = ["/login"]

    assert run_startup_config_warnings(cfg) == []


def test_startup_checks_never_raise_and_never_mutate_config() -> None:
    cfg = WaffyConfig()
    before = cfg.model_dump()

    run_startup_config_warnings(cfg)
    run_startup_config_warnings(cfg)  # idempotent, callable repeatedly

    assert cfg.model_dump() == before  # never mutates config
