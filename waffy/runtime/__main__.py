"""waffy/runtime/__main__.py — minimal waffy-core startup entrypoint.

Scope, honestly stated: this wires up configuration loading and the
startup-time config validation warnings (``waffy.runtime.startup_checks``)
only. It does **not** yet bind a real listener, start the IPC server, or
construct a real ``RuleStore``/pipeline — that full wiring is a separate,
larger undertaking `waffy/runtime/core_daemon.py` already documents as not
yet done ("In production this would be wired to uvicorn / hypercorn... Here
we record the stage without actually binding a port"). This entrypoint
exists so startup-time warnings have a real, runnable process to fire from,
per prompts/07's acceptance criteria — not to claim the daemon is complete.

Run: ``uv run waffy-core --config config/default_config.toml``
(or ``uv run python -m waffy.runtime --config ...``)
"""

from __future__ import annotations

import argparse
import logging
import sys

from waffy.config.models import load_config
from waffy.core.exceptions import ConfigurationError
from waffy.runtime.startup_checks import run_startup_config_warnings

logger = logging.getLogger("waffy.runtime")


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s"
    )

    parser = argparse.ArgumentParser(prog="waffy-core", description="waffy-core startup checks")
    parser.add_argument(
        "--config",
        default=None,
        help="Path to a waffy config TOML file (default: built-in defaults)",
    )
    args = parser.parse_args(argv)

    try:
        config = load_config(args.config)
    except ConfigurationError as e:
        logger.error("Configuration error: %s", e)
        return 1

    logger.info(
        "waffy-core starting: transport.mode=%s enforcement.mode=%s failure_mode=%s",
        config.transport.mode,
        config.enforcement.mode.value,
        config.enforcement.failure_mode.value,
    )

    warnings = run_startup_config_warnings(config)
    if warnings:
        logger.warning(
            "%d startup configuration warning(s) — see above; these are "
            "warnings only, startup is not blocked.",
            len(warnings),
        )
    else:
        logger.info("Startup configuration checks: no warnings.")

    logger.info(
        "Startup checks complete. Full daemon wiring (listener bind, IPC "
        "server, pipeline construction) is not yet implemented in this "
        "entrypoint — see waffy/runtime/core_daemon.py."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
