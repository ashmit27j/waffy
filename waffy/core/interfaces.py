"""Core protocols / interfaces for hardware and environment-dependent components.

Per CLAUDE.md: Every hardware/environment-dependent component gets a Protocol/interface
plus a Fake test implementation for standalone testability.
"""

from typing import Protocol, runtime_checkable

from waffy.core.models.domain import (
    AllowlistEntry,
    BanEntry,
    HttpRequestRecord,
    SecurityEvent,
    VirtualPatchRule,
)


@runtime_checkable
class UpstreamClient(Protocol):
    """Protocol for proxying HTTP requests to the upstream backend application."""

    async def forward(
        self,
        request: HttpRequestRecord,
        raw_body: bytes = b"",
    ) -> tuple[int, list[tuple[str, str]], bytes]:
        """Forward request to upstream app and return (status_code, headers, body)."""
        ...


@runtime_checkable
class RuleStore(Protocol):
    """Protocol for persistent ban entries, virtual patches, and allowlist state."""

    async def add_ban(self, ban: BanEntry) -> None:
        """Add a persistent IP/session ban."""
        ...

    async def get_ban(self, target: str) -> BanEntry | None:
        """Retrieve active ban for target IP/session if any."""
        ...

    async def list_active_bans(self) -> list[BanEntry]:
        """List all currently active bans."""
        ...

    async def remove_ban(self, ban_id: str) -> bool:
        """Remove or expire a ban."""
        ...

    async def add_allowlist_entry(self, entry: AllowlistEntry) -> None:
        """Add an allowlist entry."""
        ...

    async def list_allowlist(self) -> list[AllowlistEntry]:
        """List all active allowlist entries."""
        ...

    async def remove_allowlist_entry(self, target: str) -> bool:
        """Remove an allowlist entry."""
        ...

    async def add_virtual_patch(self, rule: VirtualPatchRule) -> None:
        """Add a virtual patch rule."""
        ...

    async def list_virtual_patches(self) -> list[VirtualPatchRule]:
        """List all active virtual patch rules."""
        ...


@runtime_checkable
class CertificateProvider(Protocol):
    """Protocol for obtaining and renewing TLS certificate material."""

    async def get_certificate(self, domain: str) -> tuple[str, str] | None:
        """Return (cert_pem, key_pem) for given domain, or None."""
        ...

    async def renew_certificate(self, domain: str) -> bool:
        """Trigger certificate renewal."""
        ...


@runtime_checkable
class ChallengeVerifier(Protocol):
    """Protocol for generating and validating challenge / CAPTCHA responses."""

    def generate_challenge(self, client_ip: str) -> dict[str, str]:
        """Generate JS proof-of-work or CAPTCHA challenge parameters."""
        ...

    def verify_solution(self, client_ip: str, solution: str) -> bool:
        """Verify client-submitted challenge solution."""
        ...

    def issue_trust_token(self, client_ip: str, ttl_seconds: int = 300) -> str:
        """Issue a short-lived signed trust token upon successful challenge."""
        ...

    def verify_trust_token(self, client_ip: str, token: str) -> bool:
        """Verify that a presented trust token is valid and unexpired."""
        ...


@runtime_checkable
class EventSink(Protocol):
    """Protocol for exporting security events to SIEM/syslog/external sinks."""

    async def emit(self, event: SecurityEvent) -> None:
        """Emit a security event asynchronously to the sink."""
        ...

    async def flush(self) -> None:
        """Flush any pending buffered events."""
        ...
