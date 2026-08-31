"""Allowlist manager and checking service."""

from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network

from waffy.core.interfaces import RuleStore
from waffy.core.models.domain import AllowlistEntry


class AllowlistManager:
    """Manages static and dynamic allowlist entries backed by RuleStore."""

    def __init__(self, rule_store: RuleStore) -> None:
        self.rule_store = rule_store

    async def is_allowlisted(self, client_ip: str) -> bool:
        """Check if client IP matches any static or dynamic allowlist entry."""
        entries = await self.rule_store.list_allowlist()
        try:
            client_obj = IPv4Address(client_ip) if "." in client_ip else IPv6Address(client_ip)
        except Exception:
            return False

        for entry in entries:
            target = entry.target.strip()
            try:
                if "/" in target:
                    net = (
                        IPv4Network(target, strict=False)
                        if "." in target
                        else IPv6Network(target, strict=False)
                    )
                    if client_obj in net:
                        return True
                elif target == client_ip:
                    return True
            except Exception:
                continue

        return False

    async def add_entry(
        self,
        target: str,
        reason: str = "Admin allowlist",
        created_by: str = "admin",
    ) -> AllowlistEntry:
        entry = AllowlistEntry(target=target, reason=reason, created_by=created_by)
        await self.rule_store.add_allowlist_entry(entry)
        return entry

    async def remove_entry(self, target: str) -> bool:
        """Remove an allowlist entry by target IP/CIDR."""
        return await self.rule_store.remove_allowlist_entry(target)
