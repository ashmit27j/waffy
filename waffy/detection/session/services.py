"""Session, Cookie, and CSRF protection services per spec §10.

Features:
1. Response cookie attribute enforcement (Secure, HttpOnly, SameSite).
2. CSRF Token generator and HMAC-SHA256 validator.
3. Credential stuffing detection: failed-login velocity per source IP and per targeted account.
"""

import hashlib
import hmac
import time
from collections import OrderedDict, deque
from typing import Literal

from waffy.config.models import CredentialStuffingConfig


class CookieSecurityRewriter:
    """Enforces Secure, HttpOnly, and SameSite attributes on proxied Set-Cookie headers."""

    def __init__(
        self,
        enforce_secure: bool = True,
        enforce_httponly: bool = True,
        samesite_policy: str = "Lax",
    ) -> None:
        self.enforce_secure = enforce_secure
        self.enforce_httponly = enforce_httponly
        self.samesite_policy = samesite_policy

    def rewrite_set_cookie_header(self, cookie_val: str) -> str:
        """Add missing security flags to Set-Cookie header value without duplicating attributes."""
        parts = [p.strip() for p in cookie_val.split(";")]
        if not parts or not parts[0]:
            return cookie_val

        existing_flags = {p.split("=")[0].lower() for p in parts[1:]}

        new_parts = [parts[0]]
        for p in parts[1:]:
            new_parts.append(p)

        if self.enforce_httponly and "httponly" not in existing_flags:
            new_parts.append("HttpOnly")

        if self.enforce_secure and "secure" not in existing_flags:
            new_parts.append("Secure")

        if self.samesite_policy and "samesite" not in existing_flags:
            new_parts.append(f"SameSite={self.samesite_policy}")

        return "; ".join(new_parts)


class CsrfProtector:
    """Stateless HMAC-SHA256 CSRF token generator and validator."""

    def __init__(self, secret_key: str = "waffy-default-csrf-secret-change-in-prod") -> None:
        self.secret_key = secret_key.encode("utf-8")

    def generate_token(self, session_id: str, timestamp: int | None = None) -> str:
        ts = timestamp if timestamp is not None else int(time.time())
        message = f"{session_id}:{ts}".encode()
        signature = hmac.new(self.secret_key, message, hashlib.sha256).hexdigest()
        return f"{ts}.{signature}"

    def validate_token(self, session_id: str, token: str, max_age_seconds: int = 3600) -> bool:
        try:
            ts_str, signature = token.split(".", 1)
            ts = int(ts_str)
        except Exception:
            return False

        # Expiration check
        now = int(time.time())
        if now - ts > max_age_seconds or ts > now + 60:
            return False

        message = f"{session_id}:{ts}".encode()
        expected_sig = hmac.new(self.secret_key, message, hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected_sig, signature)


class CredentialStuffingDetector:
    """Tracks failed login velocities per source IP and per account identity."""

    def __init__(self, config: CredentialStuffingConfig) -> None:
        self.config = config
        self.source_failures: OrderedDict[str, deque[float]] = OrderedDict()
        self.account_failures: OrderedDict[str, deque[float]] = OrderedDict()

    def is_configured(self) -> bool:
        """Whether this detector has been told what a failed login looks
        like. With no ``login_failure_routes`` configured, nothing ever
        calls ``record_failed_attempt`` for a real reason and velocity
        detection can never trip -- see ``waffy/runtime/startup_checks.py``.
        Query only; does not affect detection logic.
        """
        return bool(self.config.login_failure_routes)

    def check_velocity(
        self,
        source_ip: str,
        account: str | None = None,
        now: float | None = None,
    ) -> tuple[bool, Literal["ip", "account", ""], str]:
        """Non-mutating peek (aside from pruning expired entries) at whether
        *source_ip* or *account* already has excess failed-login attempts
        recorded in the current window -- unlike ``record_failed_attempt``,
        this never adds a new failed attempt. Used to produce evidence for
        the *current* request based on failures already recorded from prior
        responses, so a request itself never trips on its own outcome.

        Returns (is_tripped, scope, reason) where scope is "ip" or "account".
        """
        current_time = now if now is not None else time.time()
        window_start = current_time - self.config.window_seconds

        src_dq = self.source_failures.get(source_ip)
        if src_dq is not None:
            while src_dq and src_dq[0] < window_start:
                src_dq.popleft()
            if len(src_dq) > self.config.max_failed_logins_per_ip:
                reason = f"Failed login threshold exceeded for source IP ({len(src_dq)} in window)"
                return True, "ip", reason

        if account:
            acc_dq = self.account_failures.get(account)
            if acc_dq is not None:
                while acc_dq and acc_dq[0] < window_start:
                    acc_dq.popleft()
                if len(acc_dq) > self.config.max_failed_logins_per_account:
                    reason = (
                        f"Failed login threshold exceeded for account '{account}' "
                        f"({len(acc_dq)} in window)"
                    )
                    return True, "account", reason

        return False, "", ""

    def record_failed_attempt(
        self,
        source_ip: str,
        account: str | None = None,
        now: float | None = None,
    ) -> tuple[bool, str]:
        """Record a failed login attempt and check if velocity thresholds are tripped.

        Returns (is_tripped, reason).
        """
        current_time = now if now is not None else time.time()
        window_start = current_time - self.config.window_seconds

        # 1. Per-source tracking
        if source_ip not in self.source_failures:
            if len(self.source_failures) >= 10000:
                self.source_failures.popitem(last=False)
            self.source_failures[source_ip] = deque()
        src_dq = self.source_failures[source_ip]
        self.source_failures.move_to_end(source_ip)

        while src_dq and src_dq[0] < window_start:
            src_dq.popleft()
        src_dq.append(current_time)

        if len(src_dq) > self.config.max_failed_logins_per_ip:
            return True, f"Failed login threshold exceeded for source IP ({len(src_dq)} in window)"

        # 2. Per-account tracking
        if account:
            if account not in self.account_failures:
                if len(self.account_failures) >= 10000:
                    self.account_failures.popitem(last=False)
                self.account_failures[account] = deque()
            acc_dq = self.account_failures[account]
            self.account_failures.move_to_end(account)

            while acc_dq and acc_dq[0] < window_start:
                acc_dq.popleft()
            acc_dq.append(current_time)

            if len(acc_dq) > self.config.max_failed_logins_per_account:
                msg = (
                    f"Failed login threshold exceeded for account '{account}' "
                    f"({len(acc_dq)} in window)"
                )
                return True, msg

        return False, ""
