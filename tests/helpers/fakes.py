"""Fake / in-memory test doubles for waffy interfaces per CLAUDE.md."""

import uuid
from datetime import UTC, datetime

from waffy.core.interfaces import (
    CertificateProvider,
    ChallengeVerifier,
    EventSink,
    RuleStore,
    UpstreamClient,
)
from waffy.core.models.domain import (
    AllowlistEntry,
    BanEntry,
    HttpRequestRecord,
    SecurityEvent,
    VirtualPatchRule,
)


class FakeUpstreamClient(UpstreamClient):
    """Fake UpstreamClient that returns pre-configured responses or echoes."""

    def __init__(
        self,
        status_code: int = 200,
        headers: list[tuple[str, str]] | None = None,
        body: bytes = b"OK",
    ) -> None:
        self.status_code = status_code
        self.headers = headers or [("content-type", "text/plain")]
        self.body = body
        self.recorded_requests: list[tuple[HttpRequestRecord, bytes]] = []

    async def forward(
        self,
        request: HttpRequestRecord,
        raw_body: bytes = b"",
    ) -> tuple[int, list[tuple[str, str]], bytes]:
        self.recorded_requests.append((request, raw_body))
        return (self.status_code, self.headers, self.body)


class FakeRuleStore(RuleStore):
    """In-memory Fake RuleStore for testing."""

    def __init__(self) -> None:
        self.bans: dict[str, BanEntry] = {}
        self.allowlist: dict[str, AllowlistEntry] = {}
        self.virtual_patches: dict[str, VirtualPatchRule] = {}

    async def add_ban(self, ban: BanEntry) -> None:
        self.bans[ban.target] = ban

    async def get_ban(self, target: str) -> BanEntry | None:
        ban = self.bans.get(target)
        if ban and ban.expires_at > datetime.now(UTC):
            return ban
        return None

    async def list_active_bans(self) -> list[BanEntry]:
        now = datetime.now(UTC)
        return [b for b in self.bans.values() if b.expires_at > now]

    async def remove_ban(self, ban_id: str) -> bool:
        for k, b in list(self.bans.items()):
            if b.id == ban_id:
                del self.bans[k]
                return True
        return False

    async def add_allowlist_entry(self, entry: AllowlistEntry) -> None:
        self.allowlist[entry.target] = entry

    async def list_allowlist(self) -> list[AllowlistEntry]:
        return list(self.allowlist.values())

    async def remove_allowlist_entry(self, target: str) -> bool:
        if target in self.allowlist:
            del self.allowlist[target]
            return True
        return False

    async def add_virtual_patch(self, rule: VirtualPatchRule) -> None:
        self.virtual_patches[rule.id] = rule

    async def list_virtual_patches(self) -> list[VirtualPatchRule]:
        return list(self.virtual_patches.values())


class FakeCertificateProvider(CertificateProvider):
    """Fake CertificateProvider for tests."""

    def __init__(self, cert_pem: str = "CERT_DATA", key_pem: str = "KEY_DATA") -> None:
        self.cert_pem = cert_pem
        self.key_pem = key_pem
        self.renewals: list[str] = []

    async def get_certificate(self, domain: str) -> tuple[str, str] | None:
        _ = domain
        return (self.cert_pem, self.key_pem)

    async def renew_certificate(self, domain: str) -> bool:
        self.renewals.append(domain)
        return True


class FakeChallengeVerifier(ChallengeVerifier):
    """Fake ChallengeVerifier implementation for testing."""

    def __init__(self) -> None:
        self.valid_tokens: dict[str, str] = {}

    def generate_challenge(self, client_ip: str) -> dict[str, str]:
        return {"challenge_id": str(uuid.uuid4()), "target_ip": client_ip, "difficulty": "1"}

    def verify_solution(self, client_ip: str, solution: str) -> bool:
        _ = client_ip
        return solution == "valid_solution"

    def issue_trust_token(self, client_ip: str, ttl_seconds: int = 300) -> str:
        _ = ttl_seconds
        token = f"token_{client_ip}_{uuid.uuid4().hex[:8]}"
        self.valid_tokens[client_ip] = token
        return token

    def verify_trust_token(self, client_ip: str, token: str) -> bool:
        return self.valid_tokens.get(client_ip) == token


class FakeEventSink(EventSink):
    """Fake EventSink capturing emitted security events."""

    def __init__(self) -> None:
        self.events: list[SecurityEvent] = []
        self.flushed: bool = False

    async def emit(self, event: SecurityEvent) -> None:
        self.events.append(event)

    async def flush(self) -> None:
        self.flushed = True
