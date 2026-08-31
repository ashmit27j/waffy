"""ASGI transport and reverse proxy request handler skeleton.

In Phase 2:
Pipeline accepts ASGI connection -> parses -> normalizes -> hardcoded ALLOW -> forwards upstream.
Detection, scoring, and decision come in subsequent phases.
"""

from collections.abc import Callable, MutableMapping
from typing import Any

from starlette.requests import Request
from starlette.responses import Response

from waffy.config.models import WaffyConfig
from waffy.core.exceptions import RequestMalformedError
from waffy.core.interfaces import UpstreamClient
from waffy.http.parser import parse_asgi_request


class ProxyApplication:
    """ASGI application wrapping request parsing, pipeline inspection, and upstream proxying."""

    def __init__(
        self,
        config: WaffyConfig,
        upstream_client: UpstreamClient,
        on_request_parsed: Callable[..., Any] | None = None,
    ) -> None:
        self.config = config
        self.upstream = upstream_client
        self.on_request_parsed = on_request_parsed

    async def __call__(
        self,
        scope: MutableMapping[str, Any],
        receive: Any,
        send: Any,
    ) -> None:
        if scope["type"] != "http":
            # For websocket or lifespan events, return 400 or pass
            response = Response(b"Not Implemented", status_code=501)
            await response(scope, receive, send)
            return

        request = Request(scope, receive)

        try:
            record, raw_body = await parse_asgi_request(request, self.config.http)
        except RequestMalformedError as e:
            # Malformed request rejected with 400 Bad Request unconditionally (even in SHADOW mode)
            response = Response(
                content=f'{{"error": "Bad Request", "reason": "{e.message}"}}'.encode(),
                status_code=400,
                media_type="application/json",
            )
            await response(scope, receive, send)
            return

        # Hook for later detection phases
        if self.on_request_parsed:
            self.on_request_parsed(record, raw_body)

        # Phase 2 stub: hardcoded ALLOW passthrough to upstream client
        try:
            status_code, resp_headers, resp_body = await self.upstream.forward(record, raw_body)
        except Exception:
            # Fail-open behavior: return 502/504 or error response
            response = Response(
                content=b'{"error": "Bad Gateway", "message": "Upstream unavailable"}',
                status_code=502,
                media_type="application/json",
            )
            await response(scope, receive, send)
            return

        # Forward response back to client
        clean_headers: dict[str, str] = {}
        for hk, hv in resp_headers:
            if hk.lower() not in ("transfer-encoding", "connection"):
                clean_headers[hk] = hv

        response = Response(
            content=resp_body,
            status_code=status_code,
            headers=clean_headers,
        )
        await response(scope, receive, send)
