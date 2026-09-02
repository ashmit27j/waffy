"""Tests for waffy/enforcement/store.py (prompts/05): does enforcement state
survive a process restart, and does the drop-in RuleStore swap actually work
with the rest of the enforcement layer unmodified.
"""

import logging
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from waffy.config.models import ApiConfig, EnforcementConfig
from waffy.core.enums import EnforcementAction
from waffy.core.interfaces import RuleStore
from waffy.core.models.domain import AllowlistEntry, BanEntry, CandidateBan, VirtualPatchRule
from waffy.enforcement.allowlist import AllowlistManager
from waffy.enforcement.store import InMemoryRuleStore, SqliteRuleStore, build_rule_store
from waffy.enforcement.validation import ActionValidationChain


def _future(seconds: float = 3600.0) -> datetime:
    return datetime.now(UTC) + timedelta(seconds=seconds)


def _past(seconds: float = 10.0) -> datetime:
    return datetime.now(UTC) - timedelta(seconds=seconds)


@pytest.mark.asyncio
async def test_sqlite_rule_store_satisfies_rule_store_protocol(tmp_path: Path) -> None:
    store = SqliteRuleStore(tmp_path / "state.db")
    assert isinstance(store, RuleStore)


@pytest.mark.asyncio
async def test_in_memory_rule_store_satisfies_rule_store_protocol() -> None:
    store = InMemoryRuleStore()
    assert isinstance(store, RuleStore)


@pytest.mark.asyncio
async def test_sqlite_rule_store_survives_simulated_restart(tmp_path: Path) -> None:
    """The core claim of this task: a *new* SqliteRuleStore instance pointed
    at the same file (simulating a fresh process after a restart) sees the
    exact state the previous instance wrote.
    """
    db_path = tmp_path / "waffy-state.db"

    ban = BanEntry(target="203.0.113.9", reason="test ban", expires_at=_future())
    allow = AllowlistEntry(target="198.51.100.4", reason="test allow")
    patch = VirtualPatchRule(
        id="vp-1", cve_id="CVE-2026-0001", target_path_regex=r"^/vuln$",
        action=EnforcementAction.BLOCK,
    )

    store_before_restart = SqliteRuleStore(db_path)
    await store_before_restart.add_ban(ban)
    await store_before_restart.add_allowlist_entry(allow)
    await store_before_restart.add_virtual_patch(patch)

    # Simulate a restart: a brand new store object, same underlying file,
    # nothing shared in memory with the instance above.
    store_after_restart = SqliteRuleStore(db_path)

    active_bans = await store_after_restart.list_active_bans()
    assert [b.target for b in active_bans] == ["203.0.113.9"]

    got_ban = await store_after_restart.get_ban("203.0.113.9")
    assert got_ban is not None
    assert got_ban.reason == "test ban"

    allowlist = await store_after_restart.list_allowlist()
    assert [a.target for a in allowlist] == ["198.51.100.4"]

    patches = await store_after_restart.list_virtual_patches()
    assert [p.id for p in patches] == ["vp-1"]

    # Removal also persists across a further "restart".
    removed = await store_after_restart.remove_ban(ban.id)
    assert removed
    store_after_second_restart = SqliteRuleStore(db_path)
    assert await store_after_second_restart.list_active_bans() == []


@pytest.mark.asyncio
async def test_sqlite_rule_store_expired_ban_not_returned(tmp_path: Path) -> None:
    store = SqliteRuleStore(tmp_path / "state.db")
    expired = BanEntry(target="1.2.3.4", reason="expired", expires_at=_past())
    await store.add_ban(expired)

    assert await store.get_ban("1.2.3.4") is None
    assert await store.list_active_bans() == []


@pytest.mark.asyncio
async def test_in_memory_rule_store_does_not_survive_restart() -> None:
    """Codifies the honest negative: InMemoryRuleStore is intentionally
    ephemeral — a fresh instance never sees a previous instance's state.
    """
    store_before = InMemoryRuleStore()
    await store_before.add_ban(BanEntry(target="9.9.9.9", reason="x", expires_at=_future()))

    store_after_restart = InMemoryRuleStore()  # a real restart constructs a new object
    assert await store_after_restart.list_active_bans() == []
    assert await store_after_restart.get_ban("9.9.9.9") is None


def test_build_rule_store_warns_and_returns_ephemeral_by_default(
    caplog: pytest.LogCaptureFixture,
) -> None:
    with caplog.at_level(logging.WARNING, logger="waffy.enforcement.store"):
        store = build_rule_store(EnforcementConfig())
    assert isinstance(store, InMemoryRuleStore)
    assert any("will be" in r.message and "LOST" in r.message for r in caplog.records)


def test_build_rule_store_uses_sqlite_when_configured(tmp_path: Path) -> None:
    cfg = EnforcementConfig(state_store_path=str(tmp_path / "configured.db"))
    store = build_rule_store(cfg)
    assert isinstance(store, SqliteRuleStore)
    assert (tmp_path / "configured.db").exists()


@pytest.mark.asyncio
async def test_allowlist_manager_and_validation_chain_work_unmodified_with_sqlite_store(
    tmp_path: Path,
) -> None:
    """Proves the RuleStore swap is truly drop-in: AllowlistManager and the
    9-stage ActionValidationChain need zero changes to work against
    SqliteRuleStore instead of the in-memory store.
    """
    store = SqliteRuleStore(tmp_path / "state.db")
    await store.add_allowlist_entry(AllowlistEntry(target="10.0.0.5", reason="trusted partner"))

    manager = AllowlistManager(store)
    assert await manager.is_allowlisted("10.0.0.5") is True
    assert await manager.is_allowlisted("10.0.0.6") is False

    chain = ActionValidationChain(EnforcementConfig(), ApiConfig(), store)
    candidate = CandidateBan(target="203.0.113.50", reason="signature match", scope="global")
    approved = await chain.validate_candidate_ban(candidate)
    assert approved.target == "203.0.113.50"
    await store.add_ban(approved)

    # A second candidate for the same target is correctly rejected as a duplicate.
    with pytest.raises(Exception, match="duplicate"):
        await chain.validate_candidate_ban(candidate)

    # And the allowlisted target can never be approved as a ban candidate.
    allowlisted_candidate = CandidateBan(
        target="10.0.0.5", reason="false positive", scope="global"
    )
    with pytest.raises(Exception, match="allowlist"):
        await chain.validate_candidate_ban(allowlisted_candidate)
