# waffy Deployment Guide

This document describes the three deployment modes waffy supports, provides
concrete example configurations for each, and states the key trade-offs plainly
so that operators can make an informed choice.

> **Platform note**: waffy's IPC layer (`waffy/ipc/`) requires
> `socket.AF_UNIX` (via `asyncio.start_unix_server`) between the
> `waffy-core` and `waffy-api` processes, which native Windows Python does
> not provide — Windows-based development or testing requires WSL (see
> `README.md`'s Prerequisites section). Standalone TLS mode's JA3-capture
> pre-accept stage separately requires `socket.MSG_PEEK`, also POSIX-only
> (see the "TLS fingerprint (JA3) capture stage" section below) — an
> unrelated subsystem that happens to share the same "deploy on Linux"
> practical conclusion.

> **Fail-open / fail-closed (spec §15)**
>
> The default shipped configuration is `FAIL_OPEN` in `SHADOW` mode.  In
> SHADOW mode waffy observes and logs every request but **never blocks
> anything** — it records what it *would have* done.  An operator must
> explicitly switch to `ACTIVE` (or `ASSISTED`) mode and set a deliberate
> fail-closed policy if they want enforcement.  The reason for this default:
> an incorrectly-configured WAF is more dangerous than no WAF.  A WAF
> blocking legitimate traffic silently destroys the protected service.
> Fail-open means that if waffy encounters an internal error or is
> misconfigured, legitimate requests continue to flow.  Fail-closed means
> waffy drops the request when uncertain — appropriate only after the
> operator has validated the configuration against real traffic in SHADOW or
> ASSISTED mode.

---

## Mode 1: Standalone TLS Reverse Proxy

**Use when**: You have a public HTTPS endpoint and want waffy to own the TLS
termination boundary with the strongest process isolation.

### How it works

```
Internet ──(TLS)──► waffy-core (standalone) ──(plaintext loopback)──► backend app
```

waffy:
1. Binds port 443 (and optionally 80 with an HTTP→HTTPS redirect).
2. Terminates TLS using the configured certificate/key.
3. Decrypts the request and runs the full detection/scoring/decision pipeline.
4. Forwards the plaintext request to the upstream backend over a loopback
   TCP port or Unix socket.
5. Returns the upstream response (with response-side cookie security
   enforcement applied) to the client.

**Process isolation**: waffy and the backend run in separate processes.
A compromised backend cannot directly read waffy's enforcement state or keys.

### ACME / Let's Encrypt

Automatic certificate provisioning via ACME is a **documented stretch goal**
and is NOT implemented in this version.  Provision a certificate via certbot,
acme.sh, or your CA of choice, and point waffy at the PEM files.

### Example configuration

```toml
# config/waffy.toml

[transport]
tls_cert_path = "/etc/waffy/tls/fullchain.pem"
tls_key_path  = "/etc/waffy/tls/privkey.pem"
tls_port      = 443
http_port     = 80

[enforcement]
mode         = "active"   # Switch from "shadow" once validated
failure_mode = "fail_open"

[http]
upstream_url = "http://127.0.0.1:8000"  # Your backend

[api]
ipc_socket_path = "/run/waffy/core.sock"
```

### Starting

```bash
# Production (via systemd — see deploy/systemd/waffy-core.service)
systemctl start waffy-core

# Development / manual
uv run python -m waffy.runtime.core_daemon --config config/waffy.toml
```

### TLS fingerprint (JA3) capture stage

Standalone TLS mode's listener (`waffy.proxy.standalone.PreAcceptTlsServer`)
peeks each connection's raw ClientHello via `socket.MSG_PEEK` *before* the
TLS handshake starts, to compute a byte-accurate canonical JA3 fingerprint —
see `docs/ARCHITECTURE.md`'s prompts/13b entry for the full design and why a
custom accept loop was necessary. This is a pre-accept stage specific to
standalone mode; plaintext and embedded/middleware modes never terminate TLS
themselves and are unaffected.

```toml
[tls]
# "clienthello_peek" (default): byte-accurate canonical JA3 via a pre-accept
#   socket.MSG_PEEK. Falls back per-connection to "post_handshake"'s signal
#   if the peek fails or times out (malformed/truncated hello, non-TLS
#   traffic, a slow client) -- never fails the connection itself.
# "post_handshake": skip the peek entirely; always use the lower-fidelity,
#   post-handshake SSLObject-derived signal (the pre-prompts/13b behavior).
#   Use this to revert to the old behavior without a code change if the
#   pre-accept stage misbehaves in production.
# "disabled": capture nothing; TLS fingerprint stays neutral/absent, same
#   as plaintext mode.
ja3_capture_mode = "clienthello_peek"
```

**Linux-only**: `socket.MSG_PEEK` is POSIX-only — see this document's
platform note above (the IPC layer's `socket.AF_UNIX` requirement is a
separate, unrelated reason waffy is already Linux-coupled). Not verified on
native Windows sockets.

---

## Mode 2: Plaintext Behind Existing TLS Terminator

**Use when**: You already have Nginx, Caddy, AWS ALB, or similar doing TLS
termination and you want to insert waffy between the terminator and your
backend without replacing your TLS infrastructure.

### How it works

```
Internet ──(TLS)──► Nginx / ALB ──(plaintext)──► waffy-core (plaintext) ──► backend app
```

waffy listens on a local port (default 8080) for already-decrypted HTTP.
The Nginx/ALB forwards traffic to this port.  waffy runs the identical pipeline
and forwards to the upstream backend.

### TLS-derived signal degradation

Because waffy does not see the TLS handshake in this mode, the following
signals are **unavailable**:

| Signal | Impact |
|---|---|
| JA3 / JA3S TLS fingerprint | `BotAssessment.ja3_matched_bad` always `False` (neutral) |
| TLS cipher-suite ordering | Not available |
| TLS session ticket metadata | Not available |

All three degrade **gracefully** — a missing signal is treated as neutral, not
as an error.  User-agent heuristics, honeypot detection, timing regularity, and
all signature/ML/rate-limit detection continue to function normally.

Operators choosing this mode accept a marginal reduction in bot-detection
accuracy in exchange for infrastructure compatibility.

### Example Nginx config (upstream side)

```nginx
server {
    listen 443 ssl;
    server_name example.com;

    ssl_certificate     /etc/nginx/tls/fullchain.pem;
    ssl_certificate_key /etc/nginx/tls/privkey.pem;

    location / {
        proxy_pass         http://127.0.0.1:8080;
        proxy_set_header   Host $host;
        proxy_set_header   X-Real-IP $remote_addr;
        proxy_set_header   X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header   X-Forwarded-Proto https;
    }
}
```

### Example waffy config

```toml
# config/waffy.toml

[transport]
listen_host = "127.0.0.1"
listen_port = 8080          # waffy plaintext listener

[enforcement]
mode         = "shadow"     # Validate in SHADOW before switching to ACTIVE
failure_mode = "fail_open"

[http]
upstream_url = "http://127.0.0.1:9000"  # Your backend
```

---

## Mode 3: Embedded ASGI Middleware

**Use when**: Your application is a Python ASGI app (FastAPI, Starlette,
Django ASGI, etc.) and you want zero-hop integration without an additional
process.

### How it works

```python
from fastapi import FastAPI
from waffy.middleware.asgi import build_middleware
from waffy.http.pipeline import WaffyPipelineApplication

app = FastAPI()

# ... define your routes ...

pipeline = WaffyPipelineApplication(config=cfg, upstream_client=..., ...)
app = build_middleware(app=app, pipeline=pipeline)
```

All HTTP requests are inspected by the waffy pipeline before reaching your
FastAPI routes.  Blocked/rate-limited requests return waffy's own response;
your application code is never called.

### Documented trade-offs — read before choosing this mode

These trade-offs are stated plainly here and in
`docs/ARCHITECTURE.md`.  They are deliberate design choices an operator makes,
not hidden weaknesses:

1. **Python-only**.  This mode only protects Python ASGI applications.  A
   non-Python backend requires Mode 1 or Mode 2.

2. **No process isolation**.  In proxy modes, waffy runs as a separate OS
   process.  If the backend application is compromised via arbitrary Python
   code execution (e.g., a deserialization exploit), the attacker's code
   shares the same Python interpreter and memory space as the waffy middleware.
   They could in principle read or bypass waffy's in-process enforcement state.
   In Mode 1 and Mode 2 this cannot happen because the processes are separate.
   Choosing middleware mode is a deliberate trade-off of this isolation for
   operational simplicity (one process, simpler deployment).

3. **No upstream forwarding**.  waffy calls the wrapped ASGI app directly;
   the `UpstreamClient` in the pipeline is not used.

### Example configuration

```toml
# config/waffy.toml

[enforcement]
mode         = "shadow"     # Validate first
failure_mode = "fail_open"
```

```python
# app.py
import tomllib
from waffy.config.loader import load_config
from waffy.http.pipeline import WaffyPipelineApplication
from waffy.middleware.asgi import build_middleware
from your_app import create_app

cfg = load_config("config/waffy.toml")
pipeline = WaffyPipelineApplication(
    config=cfg,
    upstream_client=...,    # Not used in middleware mode; use FakeUpstreamClient
    rule_store=...,
    signature_engine=...,
    positive_engine=...,
)
app = build_middleware(app=create_app(), pipeline=pipeline)
```

---

## IPC Socket (`waffy-core` ↔ `waffy-api`)

The `waffy-core` process exposes a Unix domain socket for the management API
process (`waffy-api`) to read state and submit control commands.

- **Socket path**: `WaffyConfig.api.ipc_socket_path` (default `/run/waffy/core.sock`)
- **Permissions**: `0o600` (owner read/write only)
- **Protocol**: newline-delimited JSON (NDJSON), versioned (`protocol_version: "1.0"`)

The socket file should be owned by the `waffy` service user.  The `waffy-api`
process must run as the same user, or a group with access must be granted:

```bash
# systemd unit for waffy-core (Phase 9 will generate this):
# User=waffy
# Group=waffy
# RuntimeDirectory=waffy
# RuntimeDirectoryMode=0750

# If waffy-api runs as a different user, add that user to the waffy group:
usermod -aG waffy waffy-api-user
```

> **Multi-user socket enforcement**: At the OS level, `connect(2)` on a socket
> with `0o600` will be rejected by the kernel for any process whose effective
> UID does not match the socket file owner.  waffy does not add a second
> authentication layer on top of this (HMAC tokens etc.) unless the threat
> model requires it; the POSIX filesystem permission boundary is sufficient for
> same-host co-located services.

---

## Enforcement State Persistence (ban list, allowlist, virtual patches)

> **By default, waffy's active security state is in-memory only and does
> NOT survive a process restart or crash.** This includes the ban list,
> dynamic allowlist entries, and the pending-approval queue (pending bans are
> ordinary ban entries awaiting approval — they use the same store). A
> restart with no persistence configured means every active ban is gone and
> every allowlist change an operator made through the control panel or API is
> gone — the process comes back up with a clean slate.

This is logged loudly, not silently: if `enforcement.state_store_path` is
unset, `waffy.enforcement.store.build_rule_store()` logs a `WARNING` on
every startup naming exactly this risk.

**To persist state across restarts**, set `enforcement.state_store_path` to
a writable file path (inside the process's own state directory — see
`docs/MASTER_SPEC.md` §16 on `waffy-core`'s filesystem permissions):

```toml
# config/waffy.toml
[enforcement]
mode               = "active"
state_store_path   = "/var/lib/waffy/state.db"
```

This switches the backing `RuleStore` from the ephemeral
`InMemoryRuleStore` to `SqliteRuleStore` (stdlib `sqlite3`, no database
server, no new dependency) — a drop-in swap; nothing else about enforcement
behavior, the 9-stage validation chain, or the allowlist's unconditional
override changes. Ensure the parent directory is writable by the `waffy`
service user and is not shared with the `waffy-api` process's own state
(the IPC boundary, not shared file access, is the intended communication
path between the two processes — see the IPC Socket section above).

**Not yet built**: rotation/backup tooling for the SQLite file, and any
migration path for a schema change to the JSON blobs it stores. For a first
deployment, treat `state_store_path` as a single-instance file — don't share
it across multiple `waffy-core` processes.

### Exactly what `SqliteRuleStore` persists (prompts/12)

Verified directly against `waffy.core.interfaces.RuleStore`'s Protocol
methods and `waffy.enforcement.store.SqliteRuleStore`'s implementation — not
restated from a prior session's summary. `RuleStore` (and therefore
`SqliteRuleStore`) covers exactly three state categories, one SQLite table
each (`bans`, `allowlist`, `virtual_patches`):

| State | Persisted by `SqliteRuleStore`? | Notes |
|---|---|---|
| **Ban list** (`BanEntry` rows) | ✅ Yes | `add_ban` / `get_ban` / `list_active_bans` / `remove_ban`. Expired bans are filtered out by `expires_at` on read, not deleted — an expired row stays on disk until explicitly removed. |
| **Pending-approval queue** | ✅ Yes — same table as bans | There is no separate pending-approval store. A "pending ban" is an ordinary `BanEntry` row with `status = PENDING_APPROVAL`; approving or rejecting it is a normal `remove_ban` call. Persisting the ban list therefore persists the pending queue automatically — nothing extra to configure. |
| **Allowlist** (`AllowlistEntry` rows) | ✅ Yes | `add_allowlist_entry` / `list_allowlist` / `remove_allowlist_entry`. |
| **Virtual patch rules** (`VirtualPatchRule` rows) | ✅ Yes | `add_virtual_patch` / `list_virtual_patches`. No `remove_virtual_patch` exists on the Protocol today — a deployed virtual patch is not currently removable via this store at all (in-memory or SQLite); this is a pre-existing `RuleStore` Protocol gap, not something `state_store_path` changes. |

**Explicitly NOT covered by `state_store_path` / `SqliteRuleStore`** — these
stay in-memory-only regardless of whether persistence is enabled, because
they live in entirely different components, not `RuleStore`:

- The recent-events / recent-assessments ring buffers (`waffy.ipc.server.IpcStateStore`) that back `GET /api/v1/events` and `GET /api/v1/requests` — bounded in-memory deques, reset to empty on every restart.
- Rate-limiter sliding-window counters (`waffy.detection.ratelimit.engine.RateLimitEngine`) — a restart resets every client's rate-limit window to zero.
- Bot-detection's timing-regularity and TLS-fingerprint-registry trackers (`waffy.detection.bot.engine`) — reset on restart.
- Credential-stuffing failed-login velocity counters (`waffy.detection.session.services.CredentialStuffingDetector`) — reset on restart, meaning an in-progress credential-stuffing attempt's counted failures are lost across a restart.
- Anomaly model artifacts and candidates (`config.anomaly.model_dir` / `ModelGovernanceService`, see the Phase 9 / Task 10 `docs/PROGRESS.md` entry) — these already persist to their own directory on disk independent of `state_store_path` entirely; they are a separate persistence mechanism, not part of `RuleStore`.

**Recommendation — when to enable `state_store_path`**: treat it as required,
not optional, for any deployment where either is true:

1. **The process runs under a restart-prone supervisor** — systemd with
   `Restart=on-failure`/`always`, a container orchestrator's liveness-probe
   restart, or any watchdog that can kill and relaunch `waffy-core`
   unattended. Every such restart silently wipes the ban list, allowlist,
   and pending queue if `state_store_path` is unset — an operator may not
   notice until an attacker they'd already banned is back in.
2. **Losing active bans/allowlist changes on restart is unacceptable for
   the deployment's risk posture** — e.g. `enforcement.mode = "active"`
   in front of a real production application, where an operator has made
   manual allowlist/ban decisions they need to survive a crash or planned
   restart.

Conversely, a purely evaluative `SHADOW`-mode deployment being run
interactively for a short trial (no restart automation, no operator-made
allowlist/ban decisions worth keeping) can reasonably leave
`state_store_path` unset — the startup `WARNING` is informational in that
case, not a misconfiguration.

---

## Choosing a Mode

| Criterion | Standalone TLS (1) | Plaintext Proxy (2) | ASGI Middleware (3) |
|---|---|---|---|
| Non-Python backend | ✅ | ✅ | ❌ |
| Process isolation | ✅ | ✅ | ❌ |
| JA3 fingerprinting | ✅ | ❌ | ❌ |
| Existing TLS infra | ❌ | ✅ | ✅ |
| Zero extra processes | ❌ | ❌ | ✅ |
| Deployment complexity | Medium | Low | Lowest |

---

## Docker Evaluation Stack (Step C8)

For quickly trying waffy without a manual systemd setup, `Dockerfile` +
`docker-compose.yml` at the repo root bring up a three-container stack:
`demo-upstream` (a trivial stdlib-only stand-in for "your application"),
`waffy-core` (plaintext proxy mode, per `docker/waffy-config.toml`), and
`waffy-api` (the management API, connected to `waffy-core` over a shared
Unix-domain-socket volume).

**This is an evaluation/dev convenience, not a replacement for the
documented production systemd path** (`deploy/systemd/waffy-core.service`)
— parity between the two has not been independently verified, and the
Docker image deliberately skips systemd-specific concerns (sd_notify,
watchdog, graceful drain) that `waffy/runtime/core_daemon.py` handles for
the real daemon.

```bash
docker compose up --build -d
curl http://localhost:18080/hello                                          # through waffy -> demo upstream
curl -H "Authorization: Bearer CHANGE_ME" http://localhost:19090/api/v1/status
docker compose down -v
```

Host-side ports are `18080`/`19090` (not `8080`/`9090`) specifically to
avoid colliding with another local service already using the more common
ports — the containers themselves still listen on `8080`/`9090` internally.

**Defaults**: `docker/waffy-config.toml` ships `enforcement.mode = "shadow"`
and `enforcement.failure_mode = "fail_open"` explicitly (restated, not
silently relied upon), consistent with every other default in this
project. `api.management_cidrs = ["0.0.0.0/0", "::/0"]` is loosened from
the real default specifically for this eval stack — a `curl` from the host
machine arrives at the container as coming from the Docker bridge gateway,
not `127.0.0.1` — **do not carry this CIDR setting into a real deployment.**

**New entrypoint scripts** (`waffy/runtime/serve_core.py`,
`waffy/runtime/serve_api.py`): built specifically so this Docker stack has
something real to run — `waffy/runtime/core_daemon.py::CoreDaemon` (the
spec-shaped daemon with sd_notify/drain) has never actually bound a network
listener; its own code comment says so. These new scripts wire the real
plaintext-proxy pipeline and the real management API, respectively, and are
explicitly scoped as eval/Docker entrypoints, not the production daemon.

**Verified working this session, output pasted in `docs/PROGRESS.md`'s
Step C8 entry**: `docker build` succeeded for all three images; `docker
compose up` brought up a healthy stack; a `curl` through `waffy-core` to
`demo-upstream` returned the demo app's real response; sending a SQL-
injection payload through the same proxy produced a logged
`SHADOW [...]: proposed action=block, score=50.0, reasons=['High-
confidence signature match (sqli)', ...]` server-side log line — proof
waffy is actually inspecting traffic, not blindly forwarding it, while
correctly respecting `SHADOW` mode's fail-safe non-blocking contract; both
containers confirmed running as the non-root `waffy` user (uid 10001); the
management API's `/api/v1/health` returned `ipc_reachable: true`, proving
the two containers really talk to each other over the shared Unix socket
volume.

**Two real gaps found while making this actually work, not silently
patched around**:

1. **The `ml` optional-dependency group is not actually optional at import
   time.** `waffy/http/pipeline.py` unconditionally imports
   `waffy.detection.anomaly.scorer` → `waffy.detection.anomaly.baseline` →
   `joblib` at module scope — so `python -m waffy.runtime.serve_core` fails
   with `ModuleNotFoundError` before it can even start unless the `ml`
   extra is installed, even though nothing in the Docker eval entrypoints
   ever instantiates `AnomalyScorer`. Worked around in `Dockerfile` by
   installing `--extra ml` in the runtime image (a real size/build-time
   cost, not a code fix) — the actual fix (lazy-importing `joblib` inside
   `waffy/detection/anomaly/baseline.py`, or making
   `waffy/http/pipeline.py`'s anomaly import conditional) is a different
   module's concern and out of scope for this Docker-focused step.
2. **`WaffyPipelineApplication`'s observability outputs are wired to
   nothing live.** The `event_sink` constructor parameter is stored
   (`self.event_sink = event_sink`) but never actually called anywhere in
   `waffy/http/pipeline.py` — confirmed by grep. Separately,
   `waffy.ipc.server.IpcStateStore.record_event`/`record_assessment` (which
   back the `/api/v1/events` and `/api/v1/requests` management-API feeds)
   have no caller anywhere connecting them to live pipeline traffic either.
   Discovered by actually curling both endpoints after a real attack
   request through the live Docker stack and finding them empty
   (`{"ok":true,"events":[],"count":0}`) despite the request being
   genuinely scored and logged (visible in `waffy-core`'s own stdout, per
   the SHADOW log line above). This means, as shipped today, **the
   management API's events/requests feeds and any configured `EventSink`
   (e.g. the SIEM syslog integration) never receive live traffic from a
   real running pipeline** — the wiring exists on both ends
   (`WaffyPipelineApplication` accepts an `event_sink`;
   `IpcServer`/`IpcStateStore` can serve recorded events) but nothing
   connects them. This is a more significant, pre-existing finding than
   this Docker step's own scope — flagged here for a dedicated future task,
   not fixed as a side effect of writing a Docker Compose example.

---

## Fail-open / Fail-closed Summary (spec §15)

| Setting | Behaviour on waffy internal error |
|---|---|
| `fail_open` (default) | Error is logged; request is forwarded to upstream |
| `fail_closed` | Error is logged; request is rejected with 503 |

**Recommendation**: Use `fail_open` during initial rollout in SHADOW mode.
Switch to `fail_closed` only after validating that waffy does not generate
false positives on your traffic and that your upstream can sustain the
latency overhead.
