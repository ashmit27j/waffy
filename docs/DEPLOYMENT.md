# waffy Deployment Guide

This document describes the three deployment modes waffy supports, provides
concrete example configurations for each, and states the key trade-offs plainly
so that operators can make an informed choice.

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
# Production (via systemd — unit file built in Phase 9)
systemctl start waffy-core

# Development / manual
uv run python -m waffy.runtime.core_daemon --config config/waffy.toml
```

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

## Fail-open / Fail-closed Summary (spec §15)

| Setting | Behaviour on waffy internal error |
|---|---|
| `fail_open` (default) | Error is logged; request is forwarded to upstream |
| `fail_closed` | Error is logged; request is rejected with 503 |

**Recommendation**: Use `fail_open` during initial rollout in SHADOW mode.
Switch to `fail_closed` only after validating that waffy does not generate
false positives on your traffic and that your upstream can sustain the
latency overhead.
