# waffy Management API — Reference

> **Stability**: Internal management API. Not exposed to the internet.  
> **Version**: `0.1.0`  
> **OpenAPI docs**: `/api/docs` (Swagger UI), `/api/redoc` (ReDoc)

---

## Authentication

All endpoints except `GET /metrics` require **Bearer token** authentication.

```
Authorization: Bearer <api_token>
```

`api_token` is configured in `config/default_config.toml` under `[api]`:

```toml
[api]
api_token = "change-me-in-production"
bind_host = "127.0.0.1"
bind_port = 8080
management_cidrs = ["127.0.0.0/8", "10.0.0.0/8"]
```

### Management CIDR restriction

Every request's source IP must fall within one of the CIDRs listed in
`api.management_cidrs`. Requests from outside this allowlist are rejected with
`403 Forbidden` **before** the token is checked, so source-enumeration attacks
cannot recover token information via timing differences.

`X-Forwarded-For` is honoured when the API is placed behind a trusted reverse
proxy (e.g., nginx on the same host). The leftmost IP in the header is used.

> ⚠️ **Do not confuse `api.management_cidrs` with the WAF's own request
> allowlist.** They are entirely separate mechanisms:
> - `api.management_cidrs` — which hosts may reach the management API process
> - WAF allowlist — which source IPs bypass WAF inspection of proxied traffic

### Token comparison

Tokens are compared using `hmac.compare_digest` (constant-time) to prevent
timing-attack recovery of the token value.

---

## Endpoints

### Health

#### `GET /api/v1/health`

Liveness probe. Returns `200` if the API process is up. Also attempts an IPC
`get_mode` call to report whether waffy-core is reachable.

**Response:**
```json
{ "ok": true, "status": "healthy", "ipc_reachable": true }
```

#### `GET /api/v1/status`

Readiness probe. Returns current enforcement mode from waffy-core via IPC.

**Response:**
```json
{ "ok": true, "mode": "SHADOW" }
```

Returns `503` if waffy-core IPC is unavailable.

---

### Events & Requests Feed

#### `GET /api/v1/events?limit=50`

Returns recent `SecurityEvent` records from waffy-core's ring buffer.

| Parameter | Type | Default | Range |
|-----------|------|---------|-------|
| `limit`   | int  | 50      | 1–1000 |

**Response:**
```json
{
  "ok": true,
  "count": 2,
  "events": [
    {
      "id": "...", "type": "signature_match", "severity": "high",
      "timestamp": "...", "source_ip": "1.2.3.4",
      "correlation_id": "...", "summary": "SQLi in query string"
    }
  ]
}
```

#### `GET /api/v1/requests?limit=50`

Returns recent `RequestAssessment` snapshots (decision + evidence) from
waffy-core's ring buffer.

---

### Ban List

#### `GET /api/v1/bans`

List all active bans.

#### `DELETE /api/v1/bans/{ban_id}`

Expire/delete a ban by ID. The operation routes through IPC → validation chain
in waffy-core. Returns `502` if IPC fails.

---

### Allowlist

#### `GET /api/v1/allowlist`

List all allowlist entries.

#### `POST /api/v1/allowlist`

Add an IP/CIDR to the allowlist.

**Request body:**
```json
{ "target": "10.0.0.0/24", "reason": "Internal scanner" }
```

**Important:** The request routes through IPC to waffy-core, which runs the
full **9-stage validation chain** from Phase 5. Entries that fail validation
(e.g., overly broad CIDRs rejected by the safety stage, `/8` or wider) are
rejected with `422 Unprocessable Entity` and the specific validator-stage
reason is surfaced in the response body — it is never swallowed.

**Response (success):** `201 Created`
```json
{ "ok": true, "message": "Allowlisted 10.0.0.0/24." }
```

**Response (validation failure):** `422`
```json
{ "detail": "Safety stage rejected: CIDR too broad (/8)" }
```

#### `DELETE /api/v1/allowlist/{target}`

Remove an IP/CIDR from the allowlist. `target` is path-encoded.

---

### Virtual Patch Rules

#### `GET /api/v1/patches`

List all virtual patch rules from waffy-core.

---

### Pending Approval Queue

#### `GET /api/v1/pending`

List bans in `PENDING_APPROVAL` state (subset of the ban list, filtered
server-side). Pending bans are raised by waffy-core's decision engine when it
lacks sufficient evidence maturity to auto-approve under the Evidence-Maturity
Invariant.

#### `POST /api/v1/pending/{ban_id}/approve`

Approve a pending ban and make it active in waffy-core. Routes through IPC.

#### `POST /api/v1/pending/{ban_id}/reject`

Reject and discard a pending ban.

---

### Enforcement Mode

#### `GET /api/v1/mode`

Return the current enforcement mode (`SHADOW` or `ACTIVE`).

#### `POST /api/v1/mode`

Update the enforcement mode at runtime. The change takes effect immediately in
waffy-core without restart.

**Request body:**
```json
{ "mode": "ACTIVE" }
```

Valid values: `SHADOW`, `ACTIVE`.

---

### Kill-Switch

#### `POST /api/v1/killswitch`

**Destructive.** Engage the emergency kill-switch in waffy-core.

- Sets waffy-core to `SHADOW` mode (all blocking immediately suspended)
- Revokes all active bans
- Preserves allowlists
- Logs a `KILL_SWITCH_ENGAGED` audit event with severity `CRITICAL`

Requires `confirm: true` in the request body to prevent accidental activation.
A waffy-core restart is required to re-enable `ACTIVE` mode after this.

**Request body:**
```json
{ "confirm": true, "reason": "False positive storm on CDN range" }
```

**Response:** `200`
```json
{ "ok": true, "message": "Kill-switch engaged. waffy-core is now in SHADOW mode." }
```

**Response (confirm missing/false):** `400`
```json
{ "detail": "Kill-switch requires 'confirm: true' in the request body." }
```

---

### Rule Reload

#### `POST /api/v1/rules/reload`

Trigger a hot-reload of signature rules in waffy-core without restart.

**Response:**
```json
{ "ok": true, "message": "Rules reloaded. 42 rules active." }
```

---

### Metrics

#### `GET /metrics`

Prometheus 0.0.4 text-format metrics exposition. **Intentionally
unauthenticated** so Prometheus can scrape from localhost without the bearer
token. Bind the API on `127.0.0.1` (default) and use host firewall rules to
restrict access in production.

**Sample output:**
```
# HELP waffy_requests_total Total requests processed, by outcome
# TYPE waffy_requests_total counter
waffy_requests_total{outcome="allow"} 1024
waffy_requests_total{outcome="block"} 7
waffy_requests_total{outcome="shadow_allow"} 512
# HELP waffy_signature_hits_total Per-rule signature match count
# TYPE waffy_signature_hits_total counter
waffy_signature_hits_total{rule_id="SQLI-001"} 3
# HELP waffy_ban_list_size Current number of active bans
# TYPE waffy_ban_list_size gauge
waffy_ban_list_size 2
...
```

#### `GET /api/v1/metrics`

Authenticated JSON snapshot of the same counters.

**Response:**
```json
{
  "ok": true,
  "snapshot": {
    "requests": { "allow": 1024, "block": 7, "shadow_allow": 512 },
    "rate_limit_trips": 4,
    "budget_exceeded": 1,
    "ban_list_size": 2,
    "signature_hits": { "SQLI-001": 3 },
    "score_histogram": { "count": 1536, "sum": 18432.0 }
  }
}
```

---

## Error Responses

| Status | Meaning |
|--------|---------|
| `400`  | Bad request (e.g., kill-switch without `confirm: true`) |
| `403`  | Unauthenticated, wrong token, or request from outside management CIDRs |
| `422`  | Validation failure surfaced from waffy-core's validation chain |
| `502`  | waffy-core IPC call failed (core may be down or restarting) |
| `503`  | waffy-core IPC unavailable (liveness check failed) |

---

## Control Panel

A server-rendered web control panel is available at `/panel` (served by the
same `waffy-api` process on the same port). It covers:

| Page | URL |
|------|-----|
| Dashboard (mode banner, stats, recent events) | `/panel` |
| Live security event stream | `/panel/events` |
| Ban list with remove actions | `/panel/bans` |
| Allowlist management (add/remove form) | `/panel/allowlist` |
| Pending approval queue (one-click approve/reject) | `/panel/pending` |
| Kill-switch (with mandatory confirmation step) | `/panel/killswitch` |

The panel auto-refreshes every 30 seconds on the dashboard and events pages.
All mutating actions use POST forms with POST-Redirect-GET to prevent duplicate
submissions on browser reload.

---

## SIEM / EventSink Integration

Every `SecurityEvent` produced by waffy-core is forwarded to the configured
`EventSink`. Two implementations are provided:

| Sink | Use case |
|------|----------|
| `FakeEventSink` | Unit tests — collects events in memory |
| `SyslogEventSink` | Production — RFC 5424 JSON-over-UDP or TCP |

### Syslog format

Events are formatted as RFC 5424 syslog messages with the JSON event body in
the message field, compatible with **Wazuh** and other SIEM ingestion pipelines.
The event shape matches pirewall's own events so operators running both can
correlate by `correlation_id` and `source_ip`.

**Sample syslog payload:**
```
<38>1 2024-01-01T00:00:00Z waffy - - - - {"type": "signature_match", "severity": "high", ...}
```

Configure via `[integration.syslog]` in `default_config.toml`:
```toml
[integration.syslog]
host = "127.0.0.1"
port = 514
protocol = "udp"  # or "tcp"
```

---

## Process Architecture

```
┌─────────────────────────────────────────┐
│  waffy-api (this process)               │
│  FastAPI + Starlette                    │
│  Listens: 127.0.0.1:8080 (default)      │
│                                         │
│  ┌──────────────────────────────────┐   │
│  │ REST endpoints /api/v1/*         │   │
│  │ Control panel /panel/*           │   │
│  │ Metrics /metrics                 │   │
│  └───────────────┬──────────────────┘   │
│                  │ IPC (Unix socket)    │
└──────────────────┼──────────────────────┘
                   │
┌──────────────────▼──────────────────────┐
│  waffy-core (separate process)          │
│  Detection / Scoring / Enforcement      │
│  Proxy / HTTP pipeline                  │
│                                         │
│  No management API imports here.        │
└─────────────────────────────────────────┘
```

**Import-graph constraint**: `waffy/api/` and `waffy/web/` must never import
from `waffy.enforcement`, `waffy.detection`, `waffy.proxy`, or `waffy.engine`.
This is enforced by a static import-graph test in
`tests/unit/test_phase8_api.py::TestImportGraph`.
