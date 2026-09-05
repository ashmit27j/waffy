# waffy

![waffy](Waffy-banner.png)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

A standalone, per-host application-layer Web Application Firewall (WAF) built in Python. 

waffy sits inline with HTTP(S) traffic to inspect requests/responses and detect or block web application attacks (SQLi, XSS, command injection, path traversal, SSRF, SSTI, XXE, bot abuse, etc.). It combines a deterministic signature engine, positive security constraints (allowlists), and machine learning anomaly detection to produce a combined threat score.

waffy is an architectural sibling project to **pirewall** (an AI-assisted network-layer firewall). It shares design philosophies and event shapes with pirewall but has **no code dependency** on it.

## Deployment Modes

waffy can be deployed in three different ways depending on your architecture. See [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md) for full configuration details.

1. **Standalone TLS Proxy** (Recommended)
   - waffy terminates TLS directly, inspects the plaintext, and forwards to the upstream application (e.g., a Go binary or Node.js server).
   - *Best for:* Complete protection including TLS fingerprinting (JA3) for bot detection. Requires providing waffy with your certificate and private key.

2. **Plaintext Proxy**
   - Placed behind an existing TLS terminator (like Nginx, HAProxy, or AWS ALB). waffy receives plaintext HTTP, inspects it, and forwards it to the upstream app.
   - *Best for:* Existing complex ingress setups. (Note: TLS-derived signals like JA3 are lost unless forwarded via custom headers).

3. **ASGI Middleware** (Python apps only)
   - Embedded directly into a Python ASGI application (like FastAPI or Starlette). No separate waffy process is needed for the data plane.
   - *Best for:* Pure Python stacks looking for the lowest latency overhead without managing a separate proxy process.

## Prerequisites

- Python 3.12+ and [`uv`](https://docs.astral.sh/uv/).
- **Windows developers: WSL is required, not optional.** waffy's IPC layer
  (`waffy/ipc/`, between the `waffy-core` enforcement process and the
  `waffy-api` management process) uses `asyncio.start_unix_server`, which
  needs `socket.AF_UNIX` — a POSIX-only socket family that native Windows
  Python does not implement. Running `waffy-core`, the management API, or
  the test suite on Windows requires a WSL (Windows Subsystem for Linux)
  Ubuntu shell operating on the repo path (e.g. `/mnt/d/...` for a `D:`
  checkout), not a native Windows Python interpreter. This is unrelated to
  standalone TLS mode's own Linux-only assumption (`socket.MSG_PEEK` for JA3
  capture — see [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)); both point
  at "deploy on Linux" but for independent reasons.

## Quickstart

The recommended path to deploying waffy in production is a gradual escalation of enforcement, identical to the path used by pirewall. **Do not deploy straight to ACTIVE mode.**

1. **Configure and start in `SHADOW` mode.**
   - In `config.toml`, set `enforcement_mode = "SHADOW"`. 
   - waffy will log threats and emit events to the SIEM/Control Panel but will *never* block a request.

2. **Observe and tune.**
   - Let waffy run for a few days. Review the Control Panel or your SIEM for false positives.
   - Add allowlist entries for internal scanners or unusual-but-benign application traffic.

3. **Escalate to `ASSISTED` (Optional)**
   - (If supported by your integration): Allow waffy to block, but route blocks to a human review queue first.

4. **Enable `ACTIVE` mode.**
   - Once the false positive rate is near zero, set `enforcement_mode = "ACTIVE"` via the Management API or config. waffy will now actively block malicious requests and enforce rate limits.

## Documentation

- [Master Specification](docs/MASTER_SPEC.md) - The complete architecture and design spec.
- [Deployment Guide](docs/DEPLOYMENT.md) - Configuration examples for all proxy modes.
- [API Reference](docs/API.md) - Management REST API and Control Panel documentation.
- [Security & Threat Model](docs/SECURITY.md) - waffy's own security posture and limits.
- [Interoperability](docs/INTEROP.md) - Correlating events with pirewall in a SIEM.
- [Project Summary](docs/PROJECT_SUMMARY.md) - Overview of current state and limitations.
- [Implementation Progress](docs/PROGRESS.md) - Phase-by-phase tracking.

## License

waffy is licensed under the [MIT License](LICENSE).