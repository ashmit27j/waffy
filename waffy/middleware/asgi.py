"""waffy/middleware/asgi.py — Embedded ASGI middleware mode.

Architecture
------------
``WaffyMiddleware`` wraps any ASGI application and runs the **exact same**
``WaffyPipelineApplication`` pipeline that the two proxy modes use.  There is
no near-duplicate detection logic — the middleware instantiates and delegates
to the same ``WaffyPipelineApplication`` instance.

The key distinction from the proxy modes is that the middleware inserts
waffy's inspection *before* calling the wrapped application in the same
process, without a separate network hop.  If waffy decides to block or
rate-limit a request it returns its own response immediately; the wrapped
application is never called.

Documented trade-offs
---------------------
These trade-offs are stated here plainly and repeated in ``docs/ARCHITECTURE.md``
so that operators make an informed choice rather than discovering them later:

1. **Non-Python apps**: This mode only protects Python ASGI applications.
   A non-Python backend requires one of the two proxy modes.

2. **No process isolation**: In proxy mode, waffy runs as a separate process.
   If the backend application is compromised, the attacker's code cannot
   directly read or manipulate waffy's memory, keys, or enforcement state.
   In middleware mode, both the backend app and waffy share the same Python
   interpreter and address space.  A compromised application (e.g., via
   a deserialization exploit that achieves arbitrary Python code execution)
   could in principle read or bypass waffy's in-process state.
   This is a deliberate trade-off an operator chooses for the operational
   simplicity of zero extra processes; it is not a hidden weakness.

3. **Upstream forwarding not used**: In middleware mode waffy does not forward
   the request to a remote upstream; it calls the wrapped ASGI ``app`` directly.
   The ``UpstreamClient`` in the underlying pipeline is therefore not used and
   may be set to a no-op fake without behavioural consequence.

Shared pipeline guarantee
--------------------------
The unit test ``tests/integration/test_asgi_middleware.py`` contains a shared
fixture ``pipeline_factory`` that exercises both the middleware path and the
plaintext proxy path against an identical synthetic request, asserting that
the detection outcome is the same in both cases.
"""

import logging
from typing import Any

from starlette.responses import Response
from starlette.types import ASGIApp, Receive, Scope, Send

from waffy.http.pipeline import WaffyPipelineApplication

logger = logging.getLogger("waffy.middleware.asgi")


class WaffyMiddleware:
    """Drop-in ASGI middleware that runs the waffy security pipeline in-process.

    Parameters
    ----------
    app:
        The wrapped ASGI application to protect.
    pipeline:
        A fully initialised ``WaffyPipelineApplication`` instance.
        The middleware delegates all detection/scoring/enforcement to this
        shared object — the same one that can be used in proxy mode — so
        there is exactly one copy of the pipeline logic.
    """

    def __init__(self, app: ASGIApp, pipeline: WaffyPipelineApplication) -> None:
        self.app = app
        self.pipeline = pipeline

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] not in ("http", "websocket"):
            # Pass through lifespan and other ASGI message types unchanged.
            await self.app(scope, receive, send)
            return

        # Annotate scope for downstream awareness.
        scope["waffy.mode"] = "middleware"
        scope["waffy.tls_available"] = False  # TLS terminates outside or not present

        # Use the shared pipeline to evaluate this request.  The pipeline
        # application acts as an ASGI app that either returns a waffy response
        # or calls a synthetic upstream that signals "pass through."
        #
        # We intercept the send callable to detect whether the pipeline issued
        # a blocking response or allowed the request.  If allowed, we then
        # call the actual wrapped app.

        pipeline_response_started = False
        pipeline_status: list[int] = []
        pipeline_headers: list[list[tuple[bytes, bytes]]] = []
        pipeline_body: list[bytes] = []

        async def capture_send(message: Any) -> None:
            nonlocal pipeline_response_started
            if message["type"] == "http.response.start":
                pipeline_response_started = True
                pipeline_status.append(message["status"])
                pipeline_headers.append(list(message.get("headers", [])))
            elif message["type"] == "http.response.body":
                pipeline_body.append(message.get("body", b""))

        await self.pipeline(scope, receive, capture_send)

        status = pipeline_status[0] if pipeline_status else 200
        # A 2xx response from the pipeline means the request was allowed;
        # we should forward to the wrapped app.  Any other status means the
        # pipeline issued a blocking/rate-limiting response.
        if 200 <= status < 300:
            logger.debug("waffy ALLOWED request; passing to wrapped app.")
            await self.app(scope, receive, send)
        else:
            # Replay the pipeline's own response back to the client.
            logger.debug("waffy issued action with status %d; wrapped app not called.", status)
            headers = pipeline_headers[0] if pipeline_headers else []
            body = b"".join(pipeline_body)
            response = Response(
                content=body,
                status_code=status,
                headers={k.decode(): v.decode() for k, v in headers},
            )
            await response(scope, receive, send)


def build_middleware(
    app: ASGIApp,
    pipeline: WaffyPipelineApplication,
) -> "WaffyMiddleware":
    """Convenience factory that wraps ``app`` with the waffy middleware."""
    return WaffyMiddleware(app=app, pipeline=pipeline)


__all__ = [
    "WaffyMiddleware",
    "build_middleware",
]
