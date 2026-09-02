"""waffy/runtime/startup_checks.py — startup-time config validation warnings.

Per prompts/07: warns operators when a security feature is *enabled in
config* but not usably configured, so it doesn't silently no-op. This module
never changes runtime behavior and never fails startup — CLAUDE.md's
fail-open/fail-safe defaults must hold exactly as they are; a validation
"error" here is always a logged ``WARNING``, never a raised exception.

Two conditions, both confirmed by code inspection to be real gaps before
this module existed (see docs/PROGRESS.md's Phase 9 / Task 07 entry):

1. Credential-stuffing detection (``config.credential_stuffing.enabled``)
   with no ``login_failure_routes`` configured — the detector has no way to
   know what a failed login looks like, so it can never trip.
2. CSRF protection (``config.csrf.enabled``) left off while
   ``transport.mode`` is ``"embedded"`` — per spec §10, token-based CSRF
   protection is what embedded-middleware mode relies on; proxy modes use a
   different (header-based) mechanism instead.
"""

from __future__ import annotations

import logging

from waffy.config.models import WaffyConfig
from waffy.detection.session.services import CredentialStuffingDetector

logger = logging.getLogger("waffy.runtime.startup_checks")


def run_startup_config_warnings(config: WaffyConfig) -> list[str]:
    """Log a warning for each enabled-but-not-usably-configured security
    feature found in *config*. Returns the warning messages (for tests and
    for callers that want to surface them elsewhere, e.g. a control-panel
    banner) — never raises, never mutates *config*, never changes what
    startup does next.
    """
    warnings: list[str] = []

    if config.credential_stuffing.enabled:
        detector = CredentialStuffingDetector(config.credential_stuffing)
        if not detector.is_configured():
            msg = (
                "credential_stuffing.enabled is true but "
                "credential_stuffing.login_failure_routes is empty — failed-login "
                "velocity detection cannot identify a login failure and will "
                "never trip. Set login_failure_routes to the route(s)/pattern(s) "
                "whose response indicates a failed login attempt."
            )
            logger.warning(msg)
            warnings.append(msg)

    if config.transport.mode == "embedded" and not config.csrf.enabled:
        msg = (
            "transport.mode is 'embedded' (middleware mode) but csrf.enabled "
            "is false — CSRF token protection is inactive for this deployment. "
            "Set csrf.enabled = true if the wrapped application relies on "
            "waffy for CSRF protection (see docs/MASTER_SPEC.md §10)."
        )
        logger.warning(msg)
        warnings.append(msg)

    return warnings


__all__ = ["run_startup_config_warnings"]
