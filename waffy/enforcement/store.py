"""waffy/enforcement/store.py — RuleStore implementations: in-memory and disk-backed.

Audit finding that motivated this module (prompts/05; full write-up in
docs/ARCHITECTURE.md): before this file existed, ``waffy.core.interfaces.RuleStore``
had exactly one implementation anywhere in the codebase —
``tests/helpers/fakes.py::FakeRuleStore``, purely in-memory and test-only.
Every ban, allowlist entry, virtual patch, and pending-approval-queue entry
(pending bans are ``BanEntry`` rows with ``status=PENDING_APPROVAL`` in the
same store — there is no separate pending store) was lost on every process
restart, with no operator-visible warning. This module closes that gap.

Two implementations, per CLAUDE.md's Protocol/Fake pattern:

- ``InMemoryRuleStore`` — a legitimate *production* ephemeral store (not a
  test double — ``tests/helpers/fakes.py::FakeRuleStore`` remains the
  test-only Fake and is untouched by this task). This is the default when
  ``EnforcementConfig.state_store_path`` is unset, and ``build_rule_store()``
  logs a startup warning whenever it's chosen, so an operator never silently
  loses protection state without knowing it.
- ``SqliteRuleStore`` — disk-backed via stdlib ``sqlite3`` (no new
  dependency, no database server — per this task's constraint preferring "a
  local file-backed store (e.g. append-only JSON/SQLite via stdlib)").
  Selected by setting ``EnforcementConfig.state_store_path``. Every
  synchronous sqlite3 call is offloaded via ``asyncio.to_thread`` so it never
  blocks the event loop, consistent with every other ``RuleStore`` call site
  being ``async`` (including ``waffy/enforcement/allowlist.py``'s
  per-request ``is_allowlisted()`` check). Rows store each Pydantic model as
  a JSON blob (``model_dump_json`` / ``model_validate_json``) keyed by the
  same natural key the Protocol's methods already use (``target`` for bans
  and allowlist entries, ``id`` for virtual patches) — never string-formats
  attacker-influenced values into SQL; every query is parameterized.

Neither implementation changes the 9-stage validation chain
(``waffy/enforcement/validation.py``) or its ordering — this module is a
storage backend swap only.
"""

from __future__ import annotations

import asyncio
import logging
import sqlite3
from datetime import UTC, datetime
from pathlib import Path

from waffy.config.models import EnforcementConfig
from waffy.core.interfaces import RuleStore
from waffy.core.models.domain import AllowlistEntry, BanEntry, VirtualPatchRule

logger = logging.getLogger("waffy.enforcement.store")


class InMemoryRuleStore:
    """Production, intentionally-ephemeral RuleStore. Does NOT survive a
    process restart — this is the explicit default when no
    ``state_store_path`` is configured. See ``build_rule_store()``.
    """

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


class SqliteRuleStore:
    """Disk-backed RuleStore: bans, allowlist entries, and virtual patches
    survive a process restart. Implements the ``RuleStore`` Protocol.
    """

    def __init__(self, db_path: str | Path) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path))
        conn.execute("PRAGMA journal_mode=WAL")
        return conn

    def _init_schema(self) -> None:
        conn = self._connect()
        try:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS bans (
                    target TEXT PRIMARY KEY,
                    id TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    data TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_bans_id ON bans(id);

                CREATE TABLE IF NOT EXISTS allowlist (
                    target TEXT PRIMARY KEY,
                    data TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS virtual_patches (
                    id TEXT PRIMARY KEY,
                    data TEXT NOT NULL
                );
                """
            )
            conn.commit()
        finally:
            conn.close()

    # ---- bans ----

    def _add_ban_sync(self, ban: BanEntry) -> None:
        conn = self._connect()
        try:
            conn.execute(
                "INSERT OR REPLACE INTO bans (target, id, expires_at, data) VALUES (?, ?, ?, ?)",
                (ban.target, ban.id, ban.expires_at.isoformat(), ban.model_dump_json()),
            )
            conn.commit()
        finally:
            conn.close()

    async def add_ban(self, ban: BanEntry) -> None:
        await asyncio.to_thread(self._add_ban_sync, ban)

    def _get_ban_sync(self, target: str) -> BanEntry | None:
        conn = self._connect()
        try:
            row = conn.execute("SELECT data FROM bans WHERE target = ?", (target,)).fetchone()
        finally:
            conn.close()
        if row is None:
            return None
        ban = BanEntry.model_validate_json(row[0])
        if ban.expires_at <= datetime.now(UTC):
            return None
        return ban

    async def get_ban(self, target: str) -> BanEntry | None:
        return await asyncio.to_thread(self._get_ban_sync, target)

    def _list_active_bans_sync(self) -> list[BanEntry]:
        conn = self._connect()
        try:
            rows = conn.execute("SELECT data FROM bans").fetchall()
        finally:
            conn.close()
        now = datetime.now(UTC)
        bans = [BanEntry.model_validate_json(r[0]) for r in rows]
        return [b for b in bans if b.expires_at > now]

    async def list_active_bans(self) -> list[BanEntry]:
        return await asyncio.to_thread(self._list_active_bans_sync)

    def _remove_ban_sync(self, ban_id: str) -> bool:
        conn = self._connect()
        try:
            cur = conn.execute("DELETE FROM bans WHERE id = ?", (ban_id,))
            conn.commit()
            return cur.rowcount > 0
        finally:
            conn.close()

    async def remove_ban(self, ban_id: str) -> bool:
        return await asyncio.to_thread(self._remove_ban_sync, ban_id)

    # ---- allowlist ----

    def _add_allowlist_entry_sync(self, entry: AllowlistEntry) -> None:
        conn = self._connect()
        try:
            conn.execute(
                "INSERT OR REPLACE INTO allowlist (target, data) VALUES (?, ?)",
                (entry.target, entry.model_dump_json()),
            )
            conn.commit()
        finally:
            conn.close()

    async def add_allowlist_entry(self, entry: AllowlistEntry) -> None:
        await asyncio.to_thread(self._add_allowlist_entry_sync, entry)

    def _list_allowlist_sync(self) -> list[AllowlistEntry]:
        conn = self._connect()
        try:
            rows = conn.execute("SELECT data FROM allowlist").fetchall()
        finally:
            conn.close()
        return [AllowlistEntry.model_validate_json(r[0]) for r in rows]

    async def list_allowlist(self) -> list[AllowlistEntry]:
        return await asyncio.to_thread(self._list_allowlist_sync)

    def _remove_allowlist_entry_sync(self, target: str) -> bool:
        conn = self._connect()
        try:
            cur = conn.execute("DELETE FROM allowlist WHERE target = ?", (target,))
            conn.commit()
            return cur.rowcount > 0
        finally:
            conn.close()

    async def remove_allowlist_entry(self, target: str) -> bool:
        return await asyncio.to_thread(self._remove_allowlist_entry_sync, target)

    # ---- virtual patches ----

    def _add_virtual_patch_sync(self, rule: VirtualPatchRule) -> None:
        conn = self._connect()
        try:
            conn.execute(
                "INSERT OR REPLACE INTO virtual_patches (id, data) VALUES (?, ?)",
                (rule.id, rule.model_dump_json()),
            )
            conn.commit()
        finally:
            conn.close()

    async def add_virtual_patch(self, rule: VirtualPatchRule) -> None:
        await asyncio.to_thread(self._add_virtual_patch_sync, rule)

    def _list_virtual_patches_sync(self) -> list[VirtualPatchRule]:
        conn = self._connect()
        try:
            rows = conn.execute("SELECT data FROM virtual_patches").fetchall()
        finally:
            conn.close()
        return [VirtualPatchRule.model_validate_json(r[0]) for r in rows]

    async def list_virtual_patches(self) -> list[VirtualPatchRule]:
        return await asyncio.to_thread(self._list_virtual_patches_sync)


def build_rule_store(config: EnforcementConfig) -> RuleStore:
    """Build the configured RuleStore.

    Returns a ``SqliteRuleStore`` if ``config.state_store_path`` is set;
    otherwise returns an ``InMemoryRuleStore`` and logs a startup warning —
    ban/allowlist/virtual-patch state will NOT survive a process restart.
    This warning fires unconditionally whenever the ephemeral store is
    actually chosen, regardless of which entrypoint constructs it, so it
    can't be silently skipped by a future CLI/daemon wiring path.
    """
    if config.state_store_path:
        logger.info("Using disk-backed RuleStore at %s", config.state_store_path)
        return SqliteRuleStore(config.state_store_path)

    logger.warning(
        "enforcement.state_store_path is not configured — ban list, allowlist "
        "changes, and virtual-patch rules are held in memory ONLY and will be "
        "LOST on the next restart or crash. Set enforcement.state_store_path "
        "to a writable file path to persist this state across restarts. "
        "See docs/DEPLOYMENT.md."
    )
    return InMemoryRuleStore()


__all__ = ["InMemoryRuleStore", "SqliteRuleStore", "build_rule_store"]
