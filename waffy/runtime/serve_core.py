"""waffy/runtime/serve_core.py -- waffy-core Docker/evaluation entrypoint.

**Not the production daemon.** ``waffy/runtime/core_daemon.py::CoreDaemon``
is the spec-shaped startup/shutdown orchestrator (sd_notify, graceful
drain, systemd integration) but has never bound a real network listener --
its own module comment says so explicitly ("In production this would be
wired to uvicorn / hypercorn... Here we record the stage without actually
binding a port"). This module exists specifically so Step C8's Docker
Compose example has something real to run: it wires the real plaintext
proxy pipeline (signature engine loaded from disk, real ``httpx``-based
upstream client, in-memory rule store, the real IPC server) and serves it
with uvicorn. It intentionally skips ``CoreDaemon``'s sd_notify/drain/
watchdog machinery -- systemd concepts that don't apply inside a container.

Usage::

    WAFFY_CONFIG=/etc/waffy/config.toml uv run python -m waffy.runtime.serve_core

Configuration is loaded from the path in the ``WAFFY_CONFIG`` environment
variable (falling back to ``WaffyConfig()`` defaults if unset) --
``transport.upstream_url``, ``transport.host``/``port``, and
``api.ipc_socket_path`` all come from that config, same as every other
deployment mode in this project.
"""

import asyncio
import logging
import os

import uvicorn

from waffy.config.models import load_config
from waffy.detection.positive import PositiveSecurityEngine
from waffy.detection.signatures import SignatureEngine, load_all_rules_from_dir
from waffy.enforcement.allowlist import AllowlistManager
from waffy.enforcement.killswitch import KillSwitchService
from waffy.enforcement.store import InMemoryRuleStore
from waffy.http.pipeline import WaffyPipelineApplication
from waffy.http.upstream import HttpxUpstreamClient
from waffy.ipc.server import IpcServer, IpcStateStore
from waffy.proxy.plaintext import PlaintextProxyServer

logger = logging.getLogger("waffy.runtime.serve_core")


async def main() -> None:
    logging.basicConfig(level=logging.INFO)

    config_path = os.environ.get("WAFFY_CONFIG")
    config = load_config(config_path)

    signatures = load_all_rules_from_dir(config.detection.rules_dir)
    signature_engine = SignatureEngine(
        signatures,
        paranoia_level=config.detection.paranoia_level,
        time_budget_ms=config.detection.regex_budget_ms,
    )
    positive_engine = PositiveSecurityEngine([])  # no routes configured for the demo

    rule_store = InMemoryRuleStore()
    allowlist_manager = AllowlistManager(rule_store)
    killswitch = KillSwitchService(config.enforcement, rule_store)
    state_store = IpcStateStore()

    upstream_client = HttpxUpstreamClient(config.transport.upstream_url)

    pipeline = WaffyPipelineApplication(
        config=config,
        upstream_client=upstream_client,
        rule_store=rule_store,
        signature_engine=signature_engine,
        positive_engine=positive_engine,
    )
    proxy_app = PlaintextProxyServer(pipeline)

    ipc_server = IpcServer(
        config=config,
        rule_store=rule_store,
        allowlist_manager=allowlist_manager,
        killswitch=killswitch,
        state_store=state_store,
    )
    await ipc_server.start()
    logger.info(
        "waffy-core (Docker eval entrypoint) starting: proxy=%s:%d upstream=%s mode=%s",
        config.transport.host,
        config.transport.port,
        config.transport.upstream_url,
        config.enforcement.mode,
    )

    uvicorn_config = uvicorn.Config(
        app=proxy_app,
        host=config.transport.host,
        port=config.transport.port,
        lifespan="off",
        log_level="info",
    )
    server = uvicorn.Server(uvicorn_config)
    try:
        await server.serve()
    finally:
        await ipc_server.stop()


if __name__ == "__main__":
    asyncio.run(main())
