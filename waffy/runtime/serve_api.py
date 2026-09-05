"""waffy/runtime/serve_api.py -- waffy-api Docker/evaluation entrypoint.

Builds the management-API FastAPI app (``waffy.api.app.build_app``) and
serves it with uvicorn. Talks to waffy-core **only** via
``waffy.ipc.client.IpcClient`` over the Unix domain socket at
``config.api.ipc_socket_path`` -- this module imports nothing from
``waffy.enforcement``/``waffy.detection``/``waffy.proxy``/``waffy.engine``,
preserving the same process-isolation import-graph constraint
``tests/unit/test_phase8_api.py`` already enforces for ``waffy.api.app``.

Usage::

    WAFFY_CONFIG=/etc/waffy/config.toml uv run python -m waffy.runtime.serve_api
"""

import asyncio
import logging
import os

import uvicorn

from waffy.api.app import build_app
from waffy.config.models import load_config
from waffy.integration.metrics import MetricsRegistry
from waffy.ipc.client import IpcClient

logger = logging.getLogger("waffy.runtime.serve_api")


async def main() -> None:
    logging.basicConfig(level=logging.INFO)

    config_path = os.environ.get("WAFFY_CONFIG")
    config = load_config(config_path)

    ipc = IpcClient(config.api.ipc_socket_path)
    metrics = MetricsRegistry()
    app = build_app(config, ipc, metrics)

    logger.info(
        "waffy-api (Docker eval entrypoint) starting on %s:%d, IPC socket=%s",
        config.api.host,
        config.api.port,
        config.api.ipc_socket_path,
    )

    uvicorn_config = uvicorn.Config(
        app=app,
        host=config.api.host,
        port=config.api.port,
        lifespan="off",
        log_level="info",
    )
    server = uvicorn.Server(uvicorn_config)
    await server.serve()


if __name__ == "__main__":
    asyncio.run(main())
