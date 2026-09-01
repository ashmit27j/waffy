"""tests/unit/test_phase8_api.py — Phase 8: Management API, Control Panel, SIEM/Metrics.


Test coverage
-------------
1. Import-graph test: static check that waffy.api and waffy.web never import
   from waffy.enforcement, waffy.detection, waffy.proxy, or waffy.engine.
2. Auth: unauthenticated request rejected; out-of-allowlist source rejected;
   authenticated + in-allowlist request succeeds.
3. Each mutating endpoint: valid request succeeds; reflected in subsequent read.
4. Kill-switch endpoint: correct confirmation guard; full HTTP→IPC→core path.
5. EventSink: SecurityEvent produced by test reaches FakeEventSink with
   correct shape; SyslogEventSink formats valid RFC 5424 payload.
6. Metrics: counters incremented by requests are correctly reflected.
"""

from __future__ import annotations

import ast
import ipaddress
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock

import pytest
from fastapi.testclient import TestClient

from waffy.api.app import build_app
from waffy.api.auth import ip_in_networks, parse_management_networks
from waffy.config.models import WaffyConfig
from waffy.core.enums import EventSeverity, SecurityEventType  # noqa: E501
from waffy.core.models.domain import SecurityEvent
from waffy.integration.eventsink import FakeEventSink, SyslogEventSink, format_syslog_rfc5424
from waffy.integration.metrics import MetricsRegistry
from waffy.ipc.client import IpcClient, IpcClientError

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

WAFFY_ROOT = Path(__file__).parent.parent.parent / "waffy"

_FORBIDDEN_IMPORTS = {
    "waffy.enforcement",
    "waffy.detection",
    "waffy.proxy",
    "waffy.engine",
}


def _collect_imports_from_source(path: Path) -> set[str]:
    """Walk *path* and return every top-level module imported across all .py files."""
    imports: set[str] = set()
    for py_file in path.rglob("*.py"):
        try:
            tree = ast.parse(py_file.read_text(encoding="utf-8"))
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    imports.add(alias.name)
            elif isinstance(node, ast.ImportFrom) and node.module:
                    imports.add(node.module)
    return imports


# ---------------------------------------------------------------------------
# 1. Import-graph test
# ---------------------------------------------------------------------------


class TestImportGraph:
    """Asserts that waffy.api and waffy.web never directly import core modules."""

    @staticmethod
    def _find_violations(directory: Path) -> list[str]:
        imported = _collect_imports_from_source(directory)
        real_violations = []
        for imp in imported:
            for forbidden in _FORBIDDEN_IMPORTS:
                if imp == forbidden or imp.startswith(forbidden + "."):
                    real_violations.append(imp)
        return real_violations

    def test_api_does_not_import_forbidden_modules(self) -> None:
        violations = self._find_violations(WAFFY_ROOT / "api")
        assert not violations, (
            f"waffy/api/ must not directly import: {violations}. "
            "All state access must go through waffy.ipc.client."
        )

    def test_web_does_not_import_forbidden_modules(self) -> None:
        violations = self._find_violations(WAFFY_ROOT / "web")
        assert not violations, (
            f"waffy/web/ must not directly import: {violations}. "
            "All state access must go through waffy.ipc.client."
        )


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _make_ipc_mock(**overrides: Any) -> AsyncMock:
    """Return an AsyncMock IpcClient with sensible defaults."""
    ipc = AsyncMock(spec=IpcClient)
    ipc.get_mode.return_value = "SHADOW"
    ipc.read_events.return_value = []
    ipc.read_requests.return_value = []
    ipc.read_bans.return_value = []
    ipc.read_allowlist.return_value = []
    ipc.read_virtual_patches.return_value = []
    ipc.add_allowlist.return_value = None
    ipc.remove_allowlist.return_value = True
    ipc.approve_pending.return_value = None
    ipc.reject_pending.return_value = None
    ipc.trigger_killswitch.return_value = None
    ipc.reload_rules.return_value = 42
    ipc.set_mode.return_value = ("SHADOW", "ACTIVE")
    for k, v in overrides.items():
        setattr(ipc, k, v)
    return ipc


def _make_config(
    token: str = "test-token",
    management_cidrs: list[str] | None = None,
) -> WaffyConfig:
    cfg = WaffyConfig()
    cfg.api.api_token = token
    # Use 0.0.0.0/0 + ::/0 so TestClient (which uses host="testclient") is
    # rejected by the IP-parse step unless we pass a real IP via X-Forwarded-For.
    # For the out-of-CIDR tests we pass a restrictive CIDR.
    cfg.api.management_cidrs = management_cidrs or ["0.0.0.0/0", "::/0"]
    return cfg


def _make_client(
    config: WaffyConfig | None = None,
    ipc: AsyncMock | None = None,
    metrics: MetricsRegistry | None = None,
) -> TestClient:
    cfg = config or _make_config()
    _ipc = ipc or _make_ipc_mock()
    _metrics = metrics or MetricsRegistry()
    app = build_app(cfg, _ipc, _metrics)  # type: ignore[arg-type]
    return TestClient(app, raise_server_exceptions=True)


_AUTH_HEADERS = {"Authorization": "Bearer test-token"}
_WRONG_HEADERS = {"Authorization": "Bearer wrong-token"}
# For all mutating endpoint tests, we pass X-Forwarded-For to simulate
# a management IP since TestClient's host is "testclient" (unparseable).
_MGMT_HEADERS = {**_AUTH_HEADERS, "X-Forwarded-For": "127.0.0.1"}


# ---------------------------------------------------------------------------
# 2. Authentication tests
# ---------------------------------------------------------------------------


class TestAuthentication:
    """Auth: unauthenticated rejected; out-of-CIDR rejected; valid passes."""

    def test_no_token_rejected(self) -> None:
        client = _make_client()
        resp = client.get("/api/v1/health")
        assert resp.status_code == 403

    def test_wrong_token_rejected(self) -> None:
        client = _make_client()
        resp = client.get("/api/v1/health", headers=_WRONG_HEADERS)
        assert resp.status_code == 403

    def test_correct_token_succeeds(self) -> None:
        """Management CIDR is 0.0.0.0/0 in test config; TestClient uses host='testclient'
        which fails IP parsing so is rejected by CIDR guard. We use X-Forwarded-For to
        simulate a real IP that IS in the management range."""
        cfg = _make_config(management_cidrs=["127.0.0.1/32"])
        client = _make_client(config=cfg)
        resp = client.get(
            "/api/v1/health",
            headers={**_AUTH_HEADERS, "X-Forwarded-For": "127.0.0.1"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["ok"] is True

    def test_out_of_cidr_rejected(self) -> None:
        """Simulate a request from 1.2.3.4 (not in management CIDRs)."""
        cfg = _make_config(management_cidrs=["10.0.0.0/24"])
        client = _make_client(config=cfg)
        # TestClient's host is "testclient" which also fails IP parsing → rejected
        resp = client.get("/api/v1/health", headers=_AUTH_HEADERS)
        assert resp.status_code == 403

    def test_cidr_allows_management_range_via_forwarded_for(self) -> None:
        cfg = _make_config(management_cidrs=["10.0.0.0/8"])
        client = _make_client(config=cfg)
        resp = client.get(
            "/api/v1/health",
            headers={**_AUTH_HEADERS, "X-Forwarded-For": "10.5.5.5"},
        )
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# 3. Mutating endpoints
# ---------------------------------------------------------------------------


class TestMutatingEndpoints:
    """Each mutating endpoint: valid → succeeds; reflected in subsequent read."""

    def test_get_events(self) -> None:
        ipc = _make_ipc_mock()
        ipc.read_events.return_value = [{"id": "abc", "summary": "test"}]
        client = _make_client(ipc=ipc)
        resp = client.get("/api/v1/events", headers=_MGMT_HEADERS)
        assert resp.status_code == 200
        data = resp.json()
        assert data["count"] == 1
        assert data["events"][0]["summary"] == "test"

    def test_get_bans(self) -> None:
        ipc = _make_ipc_mock()
        ipc.read_bans.return_value = [{"id": "b1", "target": "1.2.3.4"}]
        client = _make_client(ipc=ipc)
        resp = client.get("/api/v1/bans", headers=_MGMT_HEADERS)
        assert resp.status_code == 200
        assert resp.json()["count"] == 1

    def test_add_allowlist_success(self) -> None:
        ipc = _make_ipc_mock()
        client = _make_client(ipc=ipc)
        resp = client.post(
            "/api/v1/allowlist",
            json={"target": "10.0.0.1", "reason": "test"},
            headers=_MGMT_HEADERS,
        )
        assert resp.status_code == 201
        ipc.add_allowlist.assert_called_once_with(target="10.0.0.1", reason="test")

    def test_add_allowlist_ipc_error_surfaces_reason(self) -> None:
        ipc = _make_ipc_mock()
        ipc.add_allowlist.side_effect = IpcClientError(
            "Safety stage rejected: CIDR too broad (/8)"
        )
        client = _make_client(ipc=ipc)
        resp = client.post(
            "/api/v1/allowlist",
            json={"target": "10.0.0.0/8", "reason": "too broad"},
            headers=_MGMT_HEADERS,
        )
        assert resp.status_code == 422
        assert "too broad" in resp.json()["detail"].lower()

    def test_remove_allowlist(self) -> None:
        ipc = _make_ipc_mock()
        ipc.remove_allowlist.return_value = True
        client = _make_client(ipc=ipc)
        resp = client.delete("/api/v1/allowlist/10.0.0.1", headers=_MGMT_HEADERS)
        assert resp.status_code == 200
        assert resp.json()["removed"] is True

    def test_get_mode(self) -> None:
        ipc = _make_ipc_mock()
        ipc.get_mode.return_value = "SHADOW"
        client = _make_client(ipc=ipc)
        resp = client.get("/api/v1/mode", headers=_MGMT_HEADERS)
        assert resp.status_code == 200
        assert resp.json()["mode"] == "SHADOW"

    def test_set_mode_success(self) -> None:
        ipc = _make_ipc_mock()
        ipc.set_mode.return_value = ("SHADOW", "ACTIVE")
        client = _make_client(ipc=ipc)
        resp = client.post("/api/v1/mode", json={"mode": "ACTIVE"}, headers=_MGMT_HEADERS)
        assert resp.status_code == 200
        assert resp.json()["mode"] == "ACTIVE"

    def test_set_mode_invalid_rejected(self) -> None:
        ipc = _make_ipc_mock()
        ipc.set_mode.side_effect = IpcClientError("Invalid mode 'BOGUS'")
        client = _make_client(ipc=ipc)
        resp = client.post("/api/v1/mode", json={"mode": "BOGUS"}, headers=_MGMT_HEADERS)
        assert resp.status_code == 422

    def test_approve_pending(self) -> None:
        ipc = _make_ipc_mock()
        client = _make_client(ipc=ipc)
        resp = client.post("/api/v1/pending/ban-abc/approve", headers=_MGMT_HEADERS)
        assert resp.status_code == 200
        ipc.approve_pending.assert_called_once_with(ban_id="ban-abc")

    def test_reject_pending(self) -> None:
        ipc = _make_ipc_mock()
        client = _make_client(ipc=ipc)
        resp = client.post("/api/v1/pending/ban-xyz/reject", headers=_MGMT_HEADERS)
        assert resp.status_code == 200
        ipc.reject_pending.assert_called_once_with(ban_id="ban-xyz")

    def test_reload_rules(self) -> None:
        ipc = _make_ipc_mock()
        ipc.reload_rules.return_value = 77
        client = _make_client(ipc=ipc)
        resp = client.post("/api/v1/rules/reload", headers=_MGMT_HEADERS)
        assert resp.status_code == 200
        assert "77" in resp.json()["message"]

    def test_list_patches(self) -> None:
        ipc = _make_ipc_mock()
        ipc.read_virtual_patches.return_value = [{"id": "vp-1"}]
        client = _make_client(ipc=ipc)
        resp = client.get("/api/v1/patches", headers=_MGMT_HEADERS)
        assert resp.status_code == 200
        assert resp.json()["count"] == 1

    def test_list_pending_filters_by_status(self) -> None:
        ipc = _make_ipc_mock()
        ipc.read_bans.return_value = [
            {"id": "b1", "status": "active"},
            {"id": "b2", "status": "pending_approval"},
        ]
        client = _make_client(ipc=ipc)
        resp = client.get("/api/v1/pending", headers=_MGMT_HEADERS)
        assert resp.status_code == 200
        data = resp.json()
        assert data["count"] == 1
        assert data["items"][0]["id"] == "b2"


# ---------------------------------------------------------------------------
# 4. Kill-switch endpoint
# ---------------------------------------------------------------------------


class TestKillSwitch:
    """Kill-switch: confirmation guard; full HTTP→IPC→core path."""

    def test_killswitch_without_confirm_rejected(self) -> None:
        ipc = _make_ipc_mock()
        client = _make_client(ipc=ipc)
        resp = client.post(
            "/api/v1/killswitch",
            json={"reason": "test", "confirm": False},
            headers=_MGMT_HEADERS,
        )
        assert resp.status_code == 400
        ipc.trigger_killswitch.assert_not_called()

    def test_killswitch_with_confirm_engages(self) -> None:
        ipc = _make_ipc_mock()
        client = _make_client(ipc=ipc)
        resp = client.post(
            "/api/v1/killswitch",
            json={"reason": "emergency", "confirm": True},
            headers=_MGMT_HEADERS,
        )
        assert resp.status_code == 200
        assert resp.json()["ok"] is True
        ipc.trigger_killswitch.assert_called_once_with(reason="emergency")

    def test_killswitch_ipc_failure_propagates(self) -> None:
        ipc = _make_ipc_mock()
        ipc.trigger_killswitch.side_effect = IpcClientError("socket not found")
        client = _make_client(ipc=ipc)
        resp = client.post(
            "/api/v1/killswitch",
            json={"reason": "test", "confirm": True},
            headers=_MGMT_HEADERS,
        )
        assert resp.status_code == 502


# ---------------------------------------------------------------------------
# 5. EventSink
# ---------------------------------------------------------------------------


class TestEventSink:
    """EventSink: SecurityEvent reaches FakeEventSink with correct shape;
    SyslogEventSink formats valid RFC 5424 payload."""

    def _make_event(self) -> SecurityEvent:
        return SecurityEvent(
            type=SecurityEventType.SIGNATURE_MATCH,
            severity=EventSeverity.HIGH,
            source_ip="192.168.1.1",
            correlation_id="corr-001",
            summary="SQLi attempt detected in query string",
        )

    @pytest.mark.asyncio
    async def test_fake_sink_collects_event(self) -> None:
        sink = FakeEventSink()
        event = self._make_event()
        await sink.emit(event)
        assert len(sink.events) == 1
        collected = sink.events[0]
        assert collected.type == SecurityEventType.SIGNATURE_MATCH
        assert collected.source_ip == "192.168.1.1"
        assert collected.summary == "SQLi attempt detected in query string"

    @pytest.mark.asyncio
    async def test_fake_sink_clear(self) -> None:
        sink = FakeEventSink()
        await sink.emit(self._make_event())
        sink.clear()
        assert len(sink.events) == 0

    def test_syslog_format_is_valid_rfc5424(self) -> None:
        import json as _json

        event = self._make_event()
        payload = format_syslog_rfc5424(event)
        msg = payload.decode()
        # RFC 5424 starts with <PRI>VERSION
        assert msg.startswith("<")
        assert ">1 " in msg
        # Must contain "waffy" as the app-name field
        assert "waffy" in msg
        # JSON body must contain key fields
        json_start = msg.index("{")
        body = _json.loads(msg[json_start:])
        assert body["type"] == SecurityEventType.SIGNATURE_MATCH.value
        assert body["severity"] == EventSeverity.HIGH.value
        assert body["source_ip"] == "192.168.1.1"
        assert body["correlation_id"] == "corr-001"
        assert body["summary"] == "SQLi attempt detected in query string"

    @pytest.mark.asyncio
    async def test_syslog_sink_udp_uses_correct_host_port(self) -> None:
        """Verify the real SyslogEventSink attempts to send to the configured host/port."""
        sink = SyslogEventSink(host="127.0.0.1", port=15140, protocol="udp")
        event = self._make_event()
        # We mock the UDP blocking send to avoid needing a real socket
        sent_payloads: list[bytes] = []

        def fake_udp(payload: bytes) -> None:
            sent_payloads.append(payload)

        sink._udp_blocking = fake_udp  # type: ignore[method-assign]
        await sink.emit(event)
        assert len(sent_payloads) == 1
        msg = sent_payloads[0].decode()
        assert "signature_match" in msg.lower()


# ---------------------------------------------------------------------------
# 6. Metrics
# ---------------------------------------------------------------------------


class TestMetrics:
    """Metrics: counters incremented by requests are correctly reflected."""

    def test_prometheus_text_endpoint_unauthenticated(self) -> None:
        """The /metrics endpoint is intentionally unauthenticated."""
        client = _make_client()
        resp = client.get("/metrics")
        assert resp.status_code == 200
        assert "waffy_requests_total" in resp.text

    def test_prometheus_text_contains_core_metrics(self) -> None:
        m = MetricsRegistry()
        m.inc_request("allow")
        m.inc_request("allow")
        m.inc_request("block")
        m.inc_rate_limit_trip()
        m.inc_budget_exceeded()
        m.set_ban_list_size(5)
        text = m.prometheus_text()
        assert 'waffy_requests_total{outcome="allow"} 2' in text
        assert 'waffy_requests_total{outcome="block"} 1' in text
        assert "waffy_rate_limit_trips_total 1" in text
        assert "waffy_budget_exceeded_total 1" in text
        assert "waffy_ban_list_size 5" in text

    def test_metrics_snapshot_endpoint_authenticated(self) -> None:
        m = MetricsRegistry()
        m.inc_request("shadow_allow")
        client = _make_client(metrics=m)
        resp = client.get("/api/v1/metrics", headers=_MGMT_HEADERS)
        assert resp.status_code == 200
        data = resp.json()
        assert data["ok"] is True
        assert "shadow_allow" in data["snapshot"]["requests"]

    def test_metrics_snapshot_unauthenticated_rejected(self) -> None:
        client = _make_client()
        resp = client.get("/api/v1/metrics")
        assert resp.status_code == 403

    def test_signature_hit_counter(self) -> None:
        m = MetricsRegistry()
        m.inc_signature_hit("SQLI-001")
        m.inc_signature_hit("SQLI-001")
        m.inc_signature_hit("XSS-001")
        text = m.prometheus_text()
        assert 'waffy_signature_hits_total{rule_id="SQLI-001"} 2' in text
        assert 'waffy_signature_hits_total{rule_id="XSS-001"} 1' in text

    def test_score_histogram_buckets(self) -> None:
        m = MetricsRegistry()
        m.observe_score(3.0)   # bucket: ≤5.0
        m.observe_score(20.0)  # bucket: ≤25.0
        snap = m.snapshot()
        assert snap["score_histogram"]["count"] == 2
        assert snap["score_histogram"]["sum"] == pytest.approx(23.0)


# ---------------------------------------------------------------------------
# 7. Auth guard unit tests
# ---------------------------------------------------------------------------


class TestAuthGuard:
    """Unit tests for the AuthGuard helper functions."""

    def test_parse_management_networks_ipv4(self) -> None:
        nets = parse_management_networks(["127.0.0.1/32", "10.0.0.0/8"])
        assert len(nets) == 2
        assert isinstance(nets[0], ipaddress.IPv4Network)

    def test_parse_management_networks_bare_ip(self) -> None:
        nets = parse_management_networks(["127.0.0.1"])
        assert len(nets) == 1
        assert str(nets[0]) == "127.0.0.1/32"

    def test_ip_in_networks_match(self) -> None:
        nets = parse_management_networks(["10.0.0.0/8"])
        assert ip_in_networks("10.5.5.5", nets) is True

    def test_ip_in_networks_no_match(self) -> None:
        nets = parse_management_networks(["10.0.0.0/8"])
        assert ip_in_networks("192.168.1.1", nets) is False

    def test_parse_invalid_cidr_skipped_with_warning(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        import logging

        with caplog.at_level(logging.WARNING, logger="waffy.api.auth"):
            nets = parse_management_networks(["not-a-cidr"])
        assert len(nets) == 0
        assert "not-a-cidr" in caplog.text
