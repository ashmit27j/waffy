# waffy

![waffy](Waffy-banner.png)

[![CI](https://github.com/ashmit27j/waffy/actions/workflows/ci.yml/badge.svg)](https://github.com/ashmit27j/waffy/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.12+](https://img.shields.io/badge/python-3.12%2B-blue.svg)](pyproject.toml)
[![Coverage: 82%](https://img.shields.io/badge/coverage-82%25-brightgreen.svg)](docs/PROGRESS.md)

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

### Try it in a couple of minutes (Docker)

The fastest way to see waffy actually inspecting traffic, no manual setup
required — brings up waffy-core, waffy-api, and a trivial demo backend:

```bash
docker compose up --build -d
curl http://localhost:18080/hello                 # a normal request, forwarded to the demo backend
curl "http://localhost:18080/products?id=1%20UNION%20SELECT%20null,username,password%20FROM%20users"
docker compose logs waffy-core                     # see the SQLi payload above get detected and scored
docker compose down -v
```

This is an evaluation/dev convenience, not the production deployment path
— see [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md)'s "Docker Evaluation
Stack" section for what it does and doesn't prove.

### Production rollout: gradual escalation of enforcement

The recommended path to deploying waffy in production is a gradual escalation of enforcement, identical to the path used by pirewall. **Do not deploy straight to `active` mode.**

1. **Configure and start in `shadow` mode** (the shipped default —
   nothing to change to get this).
   - In your config TOML's `[enforcement]` section: `mode = "shadow"`.
   - waffy will log threats and emit events to the SIEM/Control Panel but will *never* block a request.

2. **Observe and tune.**
   - Let waffy run for a few days. Review the Control Panel or your SIEM for false positives.
   - Add allowlist entries for internal scanners or unusual-but-benign application traffic.

3. **Escalate to `assisted` (optional).**
   - Auto-applies low-risk actions while queuing higher-risk ones for operator review via the Management API's pending-approval endpoints — see [`docs/API.md`](docs/API.md).

4. **Enable `active` mode.**
   - Once the false positive rate is near zero, set `[enforcement] mode = "active"` via config or the Management API's `POST /api/v1/mode`. waffy will now actively block malicious requests and enforce rate limits.

## Documentation

- [Master Specification](docs/MASTER_SPEC.md) - The complete architecture and design spec.
- [Deployment Guide](docs/DEPLOYMENT.md) - Configuration examples for all proxy modes.
- [API Reference](docs/API.md) - Management REST API and Control Panel documentation.
- [Security & Threat Model](docs/SECURITY.md) - waffy's own security posture and limits.
- [Interoperability](docs/INTEROP.md) - Correlating events with pirewall in a SIEM.
- [Project Summary](docs/PROJECT_SUMMARY.md) - Overview of current state and limitations.
- [Implementation Progress](docs/PROGRESS.md) - Phase-by-phase tracking.
- [Changelog](CHANGELOG.md) - Notable changes, release by release.

## Contributing

Contributions are welcome — see [`CONTRIBUTING.md`](CONTRIBUTING.md) for dev
environment setup, how to run the checks locally, and what a pull request
should include. Participation is governed by the
[Code of Conduct](CODE_OF_CONDUCT.md).

## Reporting a security vulnerability

Please don't open a public issue for a security vulnerability in waffy
itself — see [`SECURITY.md`](SECURITY.md) for the private reporting
process.

## License

waffy is licensed under the [MIT License](LICENSE).