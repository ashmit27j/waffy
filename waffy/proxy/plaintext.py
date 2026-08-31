"""waffy/proxy/plaintext.py — Plaintext-behind-existing-TLS proxy mode.

Architecture
------------
Listens on a local TCP port (or Unix socket) receiving already-decrypted HTTP
from an upstream TLS terminator (Nginx, Caddy, AWS ALB, etc.), runs the
identical detection/scoring/decision/enforcement pipeline, and forwards the
response back to the caller.

TLS-derived signal degradation
-------------------------------
In this mode the TLS handshake has already happened in a component waffy does
not control.  As a result the following signals are **unavailable**:

- **JA3 / JA3S TLS fingerprint** — the ClientHello is never seen by waffy.
  ``BotAssessment.ja3_matched_bad`` will always be ``False`` for requests
  arriving through this mode.

- **TLS session ticket / resumption metadata** — not propagated from the
  terminating proxy by default (would require custom headers).

- **Raw cipher-suite ordering** — a signal used by some JA3-adjacent
  fingerprinting approaches; unavailable for the same reason.

All three of these gaps are handled **gracefully**:
- The bot detection engine treats absent JA3 data as a neutral (0-weight) signal,
  not a crash or validation error.  A ``BotAssessment`` with ``ja3_matched_bad=False``
  is indistinguishable from a passing JA3 check, so the remaining heuristics
  (user-agent, honeypot, timing regularity) still run normally.
- The anomaly scorer does not consume JA3 data directly; it works on
  request-level features that are equally available in plaintext mode.
- No exception is raised; evidence from unavailable sources is simply absent.

Operators choosing this mode accept a marginal reduction in bot-detection
confidence in exchange for compatibility with their existing TLS infrastructure.
This trade-off is documented plainly in ``docs/DEPLOYMENT.md``.
"""

import logging

from starlette.types import ASGIApp, Receive, Scope, Send

from waffy.http.pipeline import WaffyPipelineApplication

logger = logging.getLogger("waffy.proxy.plaintext")


class PlaintextProxyServer:
    """ASGI-compatible plaintext proxy that expects pre-decrypted HTTP input.

    Usage
    -----
    Serve this via uvicorn or hypercorn on a loopback-only interface so
    the upstream TLS terminator can reach it without exposure to the public
    network::

        uvicorn waffy.proxy.plaintext:app --host 127.0.0.1 --port 8080

    JA3 and raw TLS signals are unavailable; see module docstring for the
    full list and how each degrades gracefully.
    """

    def __init__(self, pipeline: WaffyPipelineApplication) -> None:
        self.pipeline = pipeline

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        """Delegate to the shared pipeline application."""
        if scope["type"] in ("http", "websocket"):
            # Annotate scope so downstream components know TLS signals are absent.
            scope["waffy.tls_available"] = False
            scope["waffy.mode"] = "plaintext"
        await self.pipeline(scope, receive, send)


def build_plaintext_app(pipeline: WaffyPipelineApplication) -> ASGIApp:
    """Return a configured plaintext proxy ASGI application."""
    server = PlaintextProxyServer(pipeline)
    return server  # type: ignore[return-value]


__all__ = [
    "PlaintextProxyServer",
    "build_plaintext_app",
]
