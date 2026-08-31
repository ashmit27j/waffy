"""httpx-based implementation of UpstreamClient Protocol."""

import httpx

from waffy.core.interfaces import UpstreamClient
from waffy.core.models.domain import HttpRequestRecord


class HttpxUpstreamClient(UpstreamClient):
    """Production UpstreamClient forwarding HTTP requests using httpx.AsyncClient."""

    def __init__(self, upstream_base_url: str, timeout_seconds: float = 30.0) -> None:
        self.upstream_base_url = upstream_base_url.rstrip("/")
        self.timeout = timeout_seconds
        self._client: httpx.AsyncClient | None = None

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                base_url=self.upstream_base_url,
                timeout=self.timeout,
                follow_redirects=False,
            )
        return self._client

    async def forward(
        self,
        request: HttpRequestRecord,
        raw_body: bytes = b"",
    ) -> tuple[int, list[tuple[str, str]], bytes]:
        """Forward request to upstream target using the raw path and headers."""
        client = await self._get_client()

        # Build path and query
        target_path = request.raw_path or request.path
        if request.raw_query_string:
            url = f"{target_path}?{request.raw_query_string}"
        elif request.query_string:
            url = f"{target_path}?{request.query_string}"
        else:
            url = target_path

        # Filter hop-by-hop headers
        hop_by_hop = {"host", "transfer-encoding", "connection", "keep-alive"}
        filtered_headers: list[tuple[str, str]] = []
        for k, v in request.headers:
            if k.lower() not in hop_by_hop:
                filtered_headers.append((k, v))

        response = await client.request(
            method=request.method.value,
            url=url,
            headers=filtered_headers,
            content=raw_body,
        )

        resp_headers: list[tuple[str, str]] = []
        for k, v in response.headers.raw:
            resp_headers.append((
                k.decode("latin-1", errors="replace"),
                v.decode("latin-1", errors="replace"),
            ))

        return response.status_code, resp_headers, response.content

    async def close(self) -> None:
        if self._client and not self._client.is_closed:
            await self._client.aclose()
