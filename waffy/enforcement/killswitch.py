"""Kill-switch emergency controls per spec §14.

Immediately:
1. Sets EnforcementMode to SHADOW.
2. Transitions every currently active BanEntry / VirtualPatchRule to REMOVED/EXPIRED.
3. Preserves Allowlist intact.
4. Records summary SecurityEvent and returns audit summary.
"""

import logging
from datetime import UTC, datetime

from waffy.config.models import EnforcementConfig
from waffy.core.enums import (
    EnforcementMode,
    EventSeverity,
    RuleStatus,
    SecurityEventType,
)
from waffy.core.interfaces import EventSink, RuleStore
from waffy.core.models.domain import SecurityEvent

logger = logging.getLogger("waffy.enforcement.killswitch")


class KillSwitchService:
    """Emergency kill-switch service reverting waffy to SHADOW and purging active bans."""

    def __init__(
        self,
        enforcement_config: EnforcementConfig,
        rule_store: RuleStore,
        event_sink: EventSink | None = None,
    ) -> None:
        self.enforcement_config = enforcement_config
        self.rule_store = rule_store
        self.event_sink = event_sink

    async def engage(
        self,
        operator: str = "admin",
        reason: str = "Emergency operator kill-switch engaged",
    ) -> dict[str, int | str]:
        """Engage kill-switch: switch to SHADOW and revoke all active bans."""
        logger.critical("KILL_SWITCH_ENGAGED by operator '%s': %s", operator, reason)

        # 1. Switch mode to SHADOW
        self.enforcement_config.mode = EnforcementMode.SHADOW

        # 2. Revoke all active bans
        active_bans = await self.rule_store.list_active_bans()
        bans_removed = 0
        for ban in active_bans:
            ban.status = RuleStatus.REMOVED
            if await self.rule_store.remove_ban(ban.id):
                bans_removed += 1

        # 3. Virtual patches
        patches = await self.rule_store.list_virtual_patches()
        patches_disabled = 0
        for patch in patches:
            patch.status = RuleStatus.DISABLED
            patches_disabled += 1

        # 4. Audit summary event
        summary = (
            f"Kill-switch engaged by {operator}: {bans_removed} bans removed, "
            f"mode set to SHADOW"
        )
        summary_event = SecurityEvent(
            type=SecurityEventType.KILL_SWITCH_ENGAGED,
            severity=EventSeverity.CRITICAL,
            timestamp=datetime.now(UTC),
            source_ip="127.0.0.1",
            correlation_id="killswitch",
            summary=summary,
            details={
                "operator": operator,
                "reason": reason,
                "bans_removed": bans_removed,
                "patches_disabled": patches_disabled,
            },
        )

        if self.event_sink:
            await self.event_sink.emit(summary_event)

        return {
            "status": "engaged",
            "mode": EnforcementMode.SHADOW.value,
            "bans_removed": bans_removed,
            "patches_disabled": patches_disabled,
        }
