"""Integration tests for prompts/10: the anomaly model-governance/promotion
gate, exercised over the real IPC Unix-domain-socket wire protocol (not just
mocked at the API layer, which tests/unit/test_phase8_api.py already covers).

Coverage
--------
- A trained candidate is visible via ``read_candidate_models`` before
  promotion, with an ``active_comparison`` for operator review, and never
  appears in the shared ``AnomalyScorer``'s active models.
- ``promote_model`` over IPC moves the candidate's files into the active
  model directory AND triggers a live ``AnomalyScorer.reload_models()`` so
  the promotion takes effect without a process restart.
- ``reject_model`` discards a candidate without ever activating it.
- A deployment that never wires ``model_governance``/``anomaly_scorer`` into
  ``IpcServer`` gets a clean error response, not a crash.
"""

import os
import tempfile
from pathlib import Path

import pytest

from tests.helpers.fakes import FakeRuleStore
from waffy.config.models import WaffyConfig
from waffy.core.enums import HttpMethod
from waffy.core.models.domain import HttpRequestRecord
from waffy.detection.anomaly.baseline import BaselineBuilder
from waffy.detection.anomaly.governance import ModelGovernanceService
from waffy.detection.anomaly.scorer import AnomalyScorer
from waffy.enforcement.allowlist import AllowlistManager
from waffy.enforcement.killswitch import KillSwitchService
from waffy.ipc.client import IpcClient, IpcClientError
from waffy.ipc.server import IpcServer, IpcStateStore


def _corpus(n: int) -> list[tuple[HttpRequestRecord, bytes]]:
    corpus: list[tuple[HttpRequestRecord, bytes]] = []
    for i in range(n):
        req = HttpRequestRecord(
            method=HttpMethod.GET,
            path="/gov",
            query_string=f"q=term{i}",
            query_params={"q": [f"term{i}"]},
            client_ip="192.168.1.1",
        )
        corpus.append((req, b""))
    return corpus


@pytest.mark.asyncio
async def test_model_governance_end_to_end_over_real_ipc_socket(tmp_path: Path) -> None:
    model_dir = tmp_path / "models"
    governance = ModelGovernanceService(model_dir)
    builder = BaselineBuilder(min_sample_size=30, random_state=42)
    scorer = AnomalyScorer(model_dir)  # empty at first -- learning mode

    governance.train_candidate(builder, "route_gov", _corpus(50), version="cand-1")

    with tempfile.TemporaryDirectory() as tmpdir:
        socket_path = os.path.join(tmpdir, "waffy_gov.sock")
        cfg = WaffyConfig()
        cfg.api.ipc_socket_path = socket_path

        rule_store = FakeRuleStore()
        allowlist_mgr = AllowlistManager(rule_store)
        killswitch = KillSwitchService(cfg.enforcement, rule_store)
        state_store = IpcStateStore()

        server = IpcServer(
            config=cfg,
            rule_store=rule_store,
            allowlist_manager=allowlist_mgr,
            killswitch=killswitch,
            state_store=state_store,
            model_governance=governance,
            anomaly_scorer=scorer,
        )
        await server.start()

        try:
            client = IpcClient(socket_path=socket_path)

            # Visible via the management path before promotion.
            candidates = await client.read_candidate_models()
            assert len(candidates) == 1
            assert candidates[0]["route_id"] == "route_gov"
            assert candidates[0]["active_comparison"] == {"active_exists": False}

            # Not yet active: the live scorer sees nothing for this route.
            assert "route_gov" not in scorer.models

            await client.promote_model(route_id="route_gov", version="cand-1")

            # Promotion over IPC triggered a live reload of the shared scorer
            # -- no process restart needed.
            assert "route_gov" in scorer.models
            assert await client.read_candidate_models() == []
        finally:
            await server.stop()


@pytest.mark.asyncio
async def test_reject_model_over_real_ipc_socket_never_activates(tmp_path: Path) -> None:
    model_dir = tmp_path / "models"
    governance = ModelGovernanceService(model_dir)
    builder = BaselineBuilder(min_sample_size=30, random_state=42)
    scorer = AnomalyScorer(model_dir)

    governance.train_candidate(builder, "route_gov", _corpus(50), version="cand-1")

    with tempfile.TemporaryDirectory() as tmpdir:
        socket_path = os.path.join(tmpdir, "waffy_gov_reject.sock")
        cfg = WaffyConfig()
        cfg.api.ipc_socket_path = socket_path

        rule_store = FakeRuleStore()
        allowlist_mgr = AllowlistManager(rule_store)
        killswitch = KillSwitchService(cfg.enforcement, rule_store)
        state_store = IpcStateStore()

        server = IpcServer(
            config=cfg,
            rule_store=rule_store,
            allowlist_manager=allowlist_mgr,
            killswitch=killswitch,
            state_store=state_store,
            model_governance=governance,
            anomaly_scorer=scorer,
        )
        await server.start()

        try:
            client = IpcClient(socket_path=socket_path)
            await client.reject_model(route_id="route_gov", version="cand-1")

            assert "route_gov" not in scorer.models
            assert await client.read_candidate_models() == []

            with pytest.raises(IpcClientError):
                await client.promote_model(route_id="route_gov", version="cand-1")
        finally:
            await server.stop()


@pytest.mark.asyncio
async def test_model_governance_ipc_commands_clean_error_when_not_configured() -> None:
    """A deployment that never wires model governance into IpcServer must
    get a clean error, never a crash, from the *_model commands.
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        socket_path = os.path.join(tmpdir, "waffy_gov_none.sock")
        cfg = WaffyConfig()
        cfg.api.ipc_socket_path = socket_path

        rule_store = FakeRuleStore()
        allowlist_mgr = AllowlistManager(rule_store)
        killswitch = KillSwitchService(cfg.enforcement, rule_store)
        state_store = IpcStateStore()

        server = IpcServer(
            config=cfg,
            rule_store=rule_store,
            allowlist_manager=allowlist_mgr,
            killswitch=killswitch,
            state_store=state_store,
            # model_governance and anomaly_scorer both omitted -- default None
        )
        await server.start()

        try:
            client = IpcClient(socket_path=socket_path)
            assert await client.read_candidate_models() == []
            with pytest.raises(IpcClientError):
                await client.promote_model(route_id="x", version="y")
            with pytest.raises(IpcClientError):
                await client.reject_model(route_id="x", version="y")
        finally:
            await server.stop()
