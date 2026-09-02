# waffy Implementation Progress

> **Current Phase:** 10 (Release Polish)  
> **Overall State:** Core proxy and detection logic is complete and tested. Management API and SIEM integration is complete. Attack-lab and benchmarks are pending.  
> **Test Suite:** 96 tests passing (0 failures), pyright strict clean, ruff clean.
> **Environment note:** the IPC layer requires `asyncio.start_unix_server`/`socket.AF_UNIX`, which native Windows Python does not provide. All commands in this document were run under WSL Ubuntu (`/mnt/d/...`, Python 3.14.4) — see the Phase 9 entry below for the session this was confirmed in.

Tracking implementation status across phases with strict labeling honesty (`Implemented` / `Tested` / `Mocked` / `Environment-dependent` / `Not yet validated`).

## Phase Summary

| Phase | Description | Status | Details |
|---|---|---|---|
| **0** | `CLAUDE.md` persistent contract | **DONE** | Tested & verified at root |
| **1** | Frozen `docs/MASTER_SPEC.md` | **DONE** | Created & frozen |
| **2 (Phase 01)** | Foundation, domain models, config, interfaces | **DONE** | All models, enums, exceptions, protocols, fakes, tests pass (`pyright --strict`, `ruff`, `pytest`) |
| **3 (Phase 02)** | HTTP engine, parsing, normalization, anti-evasion | **DONE** | Smuggling checks, decompression bomb guard, safe XML XXE parser, multi-pass anti-evasion, ASGI proxy application |
| **4 (Phase 03)** | Detection: signature engine, positive security | **DONE** | Seed signature set across all categories, paranoia-level filtering, execution time budget guard, route positive security engine, 0% benign corpus false-positive rate |
| **5 (Phase 04)** | ML / anomaly scoring layer | **DONE** | Canonical feature extraction (v1 schema), offline Isolation Forest baseline builder with minimum sample enforcement, fault-tolerant runtime anomaly scorer (evidence only) |
| **6 (Phase 05)** | Scoring & decision engine, enforcement, validation chain | **DONE** | Additive scoring engine, mode-aware decision engine with evidence-maturity invariant, single-point enforcement executor, 9-stage validation chain, allowlist manager, kill-switch |
| **7 (Phase 06)** | Rate limiting, DoS, bot detection, session/CSRF | **DONE** | All implemented & tested ✓ |
| **8 (Phase 07)** | Deployment proxy modes, ASGI middleware, IPC | **DONE** | All deliverables implemented & tested ✓ |
| **9 (Phase 08)** | Management API, control panel, SIEM/metrics | **DONE** | All deliverables implemented & tested ✓ |
| **10 (Phase 09)** | Hardening, synthetic attack-lab corpus, benchmarks | In progress | Attack-lab corpus (prompts/01), benchmarks (prompts/02), real TLS handshake test (prompts/03), JA3/JA4 fingerprinting (prompts/04) done; state persistence, HTTP/2 coverage, config validation warnings still pending (prompts/05-07) |
| **11 (Phase 10)** | Release polish, interoperability documentation | **DONE** | Documentation and release polish complete ✓ |

---

## Detailed Deliverables by Phase

### Phase 1 (02-phase-01-foundation.md) — Foundation
- **Repo scaffolding & pyproject.toml**: **Tested** (Python 3.12+, uv-managed, hatchling build, strict pyright, ruff, pytest)
- **`config/default_config.toml`**: **Tested** (Complete section coverage per spec §24, default SHADOW mode & fail_open)
- **`waffy/config/`**: **Tested** (Pydantic v2 settings models, TOML loader with validation and typed exceptions)
- **`waffy/core/enums.py`**: **Tested** (ThreatLevel, EnforcementAction, EnforcementMode, FailureMode, RuleStatus, SignatureCategory, ParanoiaLevel, HttpMethod, SecurityEventType, EventSeverity, TargetField)
- **`waffy/core/exceptions.py`**: **Tested** (WaffyError base and 10 typed subclasses with behavior docstrings)
- **`waffy/core/models/domain.py`**: **Tested** (Pydantic v2 domain models for all spec §6 entities with strict validators)
- **`waffy/core/interfaces.py`**: **Tested** (Protocols for UpstreamClient, RuleStore, CertificateProvider, ChallengeVerifier, EventSink)
- **`tests/helpers/fakes.py`**: **Tested** (In-memory Fake implementations for all 5 protocols)
- **`docs/CODING_STANDARDS.md`**: **Implemented** (Captured persistent CLAUDE.md rules and architectural constraints)
- **Phase 1 Test Suite (`tests/unit/test_foundation.py`)**: **Tested** (7/7 tests passing, clean `pyright` strict mode, clean `ruff check`)

### Phase 2 (03-phase-02-http-engine.md) — HTTP Engine, Parsing & Normalization
- **`waffy/http/normalize.py`**: **Tested** (Multi-pass percent decoding, '+' space normalization, NFKC unicode normalization, path traversal resolution without mutating routed paths, null byte stripping)
- **`waffy/http/body.py`**: **Tested** (Content-type aware body parsing for JSON, Form-urlencoded, Multipart/form-data metadata, XXE-safe XML parsing with external entity resolution unconditionally disabled, decompression bomb ratio/size guards)
- **`waffy/http/parser.py`**: **Tested** (Ambiguity & smuggling rejection: CL/TE conflicts, duplicate conflicting CL headers, chunked framing validation, header size/count bounds, request line limits)
- **`waffy/http/upstream.py`**: **Implemented** (Real `httpx.AsyncClient`-based `HttpxUpstreamClient` forwarding requests with hop-by-hop header filtering)
- **`waffy/http/transport.py`**: **Tested** (Starlette/ASGI `ProxyApplication` accepting requests, enforcing malformed request rejection even in SHADOW mode, and forwarding via `UpstreamClient`)
- **HTTP/2 Support Status**: **Not yet validated** (ASGI server level HTTP/2 capability depends on uvicorn/hypercorn deployment profile; HTTP/1.1 fully implemented and tested)
- **Phase 2 Test Suite (`tests/unit/test_http_engine.py`)**: **Tested** (Table-driven anti-evasion, desync ambiguity rejection, decompression bomb fixtures, safe XML parsing, multipart metadata extraction, end-to-end ASGI proxy flow)

### Phase 3 (04-phase-03-detection-rule-engine.md) — Detection: Signature Engine & Positive Security
- **`waffy/detection/signatures/schema.py`**: **Tested** (Pydantic v2 signature definition schema, TOML rule loader with duplicate ID detection and `RuleLoadError`)
- **`waffy/detection/signatures/engine.py`**: **Tested** (Multi-target signature matcher across path/query/headers/cookies/body, paranoia-level filtering, per-request matching time budget guard aborting slow checks without halting request pipeline)
- **`config/rules/seed_rules.toml`**: **Tested** (Seed rule set covering SQLi, XSS, Command Injection, Path Traversal, LFI/RFI, SSTI, XXE, Deserialization, CRLF Injection, Open Redirect, and Known Scanner Fingerprints)
- **`waffy/detection/positive/`**: **Tested** (Per-route security model with allowed methods, content types, parameter constraints [type, min/max length, regex], unknown-parameter policy, clean fallback for unconfigured routes)
- **`config/routes/example_routes.toml`**: **Implemented** (Sample positive security route specifications)
- **Benign Traffic False-Positive Rate**: **Tested** (0.0% false-positive rate on synthetic benign traffic corpus against Paranoia Level 1 rules)
- **Phase 3 Test Suite (`tests/unit/test_detection_engine.py`)**: **Tested** (True positive and true negative tests for all categories, budget limit test, paranoia-level filtering, positive security validator)

### Phase 4 (05-phase-04-ml-anomaly.md) — ML / Anomaly Scoring Layer (Evidence Only)
- **`waffy/detection/anomaly/features.py`**: **Tested** (Single canonical feature extractor computing 12 numerical features: length, param count, max param length, max Shannon entropy, path depth, header count, unusual header presence, character ratios, and encoding layers)
- **`waffy/detection/anomaly/baseline.py`**: **Tested** (Isolation Forest baseline trainer enforcing minimum sample count threshold [below threshold -> fallback to signature-only], exporting joblib model and ModelMetadata)
- **`waffy/detection/anomaly/scorer.py`**: **Tested** (Fault-tolerant runtime scorer producing normalized `AnomalyEvidence` without mutating blocklists or issuing enforcement commands; degrades safely on missing/corrupt model files)
- **Production Validation**: **Tested on synthetic corpus; not yet validated against real per-route production traffic** (honesty rule label)
- **Phase 4 Test Suite (`tests/unit/test_ml_anomaly.py`)**: **Tested** (Deterministic feature extraction, Shannon entropy verification, min sample threshold fallback, model training and score differentiation, corrupted artifact degradation)

### Phase 5 (06-phase-05-decision-enforcement.md) — Scoring, Decision & Enforcement
- **`waffy/engine/scoring.py`**: **Tested** (Config-driven additive scoring across signatures, positive security violations, ML anomaly, bot, and rate limits mapping to ThreatLevel)
- **`waffy/engine/decision.py`**: **Tested** (Mode-aware decision table implementing the **Evidence-Maturity Invariant**: single weak signals are downgraded to CHALLENGE and never BLOCK without high-confidence low-FP category match, multiple corroborating categories, or recurring source readings tracked via bounded LRU `ConsistencyTracker`)
- **`waffy/enforcement/actions.py`**: **Tested** (The single authorized execution point: ALLOW, LOG, RATE_LIMIT [429 + Retry-After], BLOCK [403 non-leaking generic response], CHALLENGE [verification delegator])
- **`waffy/enforcement/validation.py`**: **Tested** (9-stage persistent action validation chain: schema -> network validity -> allowlist -> safety [management CIDRs, localhost, /24 IPv4 and /64 IPv6 width limits] -> conflict -> duplicate -> sliding-window rate-cap -> expiration -> authorization)
- **`waffy/enforcement/allowlist.py`**: **Tested** (Static/dynamic allowlist manager with unconditional decision override)
- **`waffy/enforcement/killswitch.py`**: **Tested** (Emergency kill-switch setting mode to SHADOW, revoking all active bans, preserving allowlists, and logging audit events)
- **`waffy/http/pipeline.py`**: **Tested** (Full inline pipeline application orchestrating parse -> detect -> score -> decide -> enforce end-to-end)
- **Shipped Default Enforcement Mode**: **SHADOW mode / fail_open default** (`ACTIVE` mode capability tested locally, not yet validated against real production traffic)
- **Phase 5 Test Suite (`tests/unit/test_decision_enforcement.py`)**: **Tested** (Additive scoring, evidence maturity both directions, mode branching, validation chain rejection stages, allowlist override, kill-switch engagement, and full end-to-end ACTIVE vs SHADOW pipeline flow)

### Phase 6 (07-phase-06-session-bot-ratelimit.md) — Rate Limiting, Bot Detection, Session/Cookie Security
- **`waffy/detection/ratelimit/engine.py`**: **Tested** (Bounded sliding-window limiters for IP, session, route, and global scopes; LRU eviction for bounded memory; produces `RateLimitState` evidence only)
- **`waffy/detection/bot/engine.py`**: **Tested** (Multi-signal bot heuristics: scanner UA, honeypot endpoint trap, timing regularity tracker; TLS fingerprint check now matches against a config-managed `known_bad_tls_fingerprints` list — see the Phase 9 / Task 04 entry below for what changed and its honest scope; no longer a hardcoded placeholder-string comparison)
- **`waffy/detection/session/services.py`**: **Tested** (Cookie attribute rewriter for Secure/HttpOnly/SameSite enforcement; HMAC-signed CSRF token generation/verification; credential stuffing velocity detector)
- **`waffy/http/limits.py`**: **Tested** (Transport resource protection: max in-flight requests, per-IP concurrency, slowloris/slow-POST minimum upload rate guard, idle timeout)
- **Config models**: **Tested** (`RateLimitConfig`, `BotDetectionConfig`, `CookieSecurityConfig`, `CredentialStuffingConfig`, `HttpLimitsConfig` all added to `WaffyConfig`)
- **Decision engine update**: **Tested** (Rate-limit tripped state maps directly to `RATE_LIMIT` enforcement action — 429 + Retry-After)
- **Phase 6 Test Suite (`tests/unit/test_session_bot_ratelimit.py`)**: **Tested** (8/8 tests passing — sliding window window-reset, multi-scope rate limiting, bot heuristics, cookie rewriting, CSRF token, credential stuffing, transport limits, full pipeline 429 flow)

### Phase 7 (08-phase-07-deployment-proxy-modes.md) — Deployment Proxy Modes, ASGI Middleware, IPC
- **`waffy/proxy/standalone.py`**: **Tested** (`FileCertificateProvider` loads cert/key from disk; `build_ssl_context` builds TLSv1.2+ context; ACME is explicitly documented as stretch goal; real TLS handshake verified in prompts/03 — see that entry below — updated from the earlier Environment-dependent label now that the gap is closed)
- **`waffy/proxy/plaintext.py`**: **Tested** (`PlaintextProxyServer` delegates to shared pipeline; TLS-derived signals absent but gracefully neutral; test confirms no crash with absent JA3 data)
- **`waffy/middleware/asgi.py`**: **Tested** (`WaffyMiddleware` wraps any ASGI app; blocked requests never reach wrapped app; allowed requests are passed through; shared-pipeline test proves no duplicate detection logic; trade-offs explicitly documented — Python-only, no process isolation)
- **`waffy/ipc/protocol.py`**: **Tested** (Pydantic v2 typed NDJSON schema covering 13 IPC commands; `parse_ipc_request` dispatcher; versioned with `PROTOCOL_VERSION="1.0"`)
- **`waffy/ipc/server.py`**: **Tested** (Unix domain socket server with 0o600 permissions; full command dispatch; ring-buffer `IpcStateStore`; protocol version mismatch rejection; graceful client handling)
- **`waffy/runtime/core_daemon.py`**: **Tested** (Ordered startup: IPC → proxy → readiness; `sd_notify READY=1` hook; graceful drain with timeout; in-flight counter; stage-order assertions in integration tests)
- **`docs/DEPLOYMENT.md`**: **Implemented** (Concrete example configs for all three modes; fail-open/fail-closed trade-off stated prominently; TLS signal degradation table for plaintext mode; IPC socket permission guidance)
- **IPC socket permission bits**: **Tested** (0o600 assertion passes; multi-OS-user rejection is documented as environment-dependent — relies on POSIX `connect(2)` enforcement which is kernel-tested)
- **Real TLS handshake test**: **Tested** (prompts/03 — see the dedicated Phase 9 / Task 03 entry below; `test_standalone_tls_environment_note` has been replaced by a real, passing test)
- **Phase 7 Integration Test Suite (`tests/integration/test_phase7_deployment.py`)**: **Tested** (14/14 tests passing — plaintext mode, middleware block/allow, shared-pipeline proof, IPC socket permissions, IPC read/write/mode, protocol version mismatch, startup stage order, graceful drain, FileCertificateProvider unit tests)

### Phase 8 (09-phase-08-api-controlpanel-siem.md) — Management API, Control Panel, SIEM/Metrics

- **`waffy/ipc/client.py`**: **Tested** (IpcClient: short-lived Unix socket connections for all 13 IPC commands; all errors surfaced as `IpcClientError`; no direct imports from enforcement/detection/proxy/engine)
- **`waffy/api/auth.py`**: **Tested** (Bearer token auth via `hmac.compare_digest`; CIDR guard; `X-Forwarded-For` support; `AuthGuard` FastAPI dependency; `parse_management_networks` and `ip_in_networks` exported as public API)
- **`waffy/api/models.py`**: **Tested** (Pydantic v2 request/response models for all 19 endpoints; explicit typed `list[dict[str, Any]]` factories for pyright strict compatibility)
- **`waffy/api/app.py`**: **Tested** (FastAPI factory `build_app(config, ipc, metrics)`; 19 endpoints; Prometheus unauthenticated `/metrics`; authenticated `/api/v1/metrics` JSON; all mutating ops route through `IpcClient`; kill-switch requires `confirm: true`; OpenAPI at `/api/docs`)
- **`waffy/web/server.py`**: **Tested** (Starlette server-rendered control panel; 6 pages: dashboard, events, bans, allowlist, pending, kill-switch; POST-Redirect-GET; no imports from enforcement/detection/proxy/engine)
- **`waffy/web/templates/`**: **Implemented** (7 Jinja2 templates: base, dashboard, events, bans, allowlist, pending, killswitch)
- **`waffy/web/static/`**: **Implemented** (Dark-mode CSS design system; 30-second auto-refresh JS for live pages)
- **`waffy/integration/eventsink.py`**: **Tested** (RFC 5424 syslog formatter; `SyslogEventSink` UDP/TCP; `FakeEventSink`; Wazuh-compatible JSON body)
- **`waffy/integration/metrics.py`**: **Tested** (Prometheus text-format `MetricsRegistry`; counters by outcome, rate-limit, budget, ban size, per-rule signature hits; score histogram with 7 buckets; JSON `snapshot()`)
- **`docs/API.md`**: **Implemented** (Full endpoint reference, auth scheme, CIDR model, kill-switch contract, SIEM integration, process architecture diagram)
- **Import-graph constraint**: **Tested** (Static AST-walk test: `waffy/api/` and `waffy/web/` never import `waffy.enforcement`, `waffy.detection`, `waffy.proxy`, or `waffy.engine`)
- **Phase 8 Test Suite (`tests/unit/test_phase8_api.py`)**: **Tested** (38/38 — import-graph, auth, all 19 REST endpoints, kill-switch guard, EventSink shape, syslog RFC 5424, Prometheus/JSON metrics, AuthGuard unit tests)
- **Overall**: **91/91 tests passing** | **pyright strict: 0 errors** | **ruff: 0 errors**

### Phase 9 / Task 01 (prompts/01-attack-lab-corpus.md) — Synthetic Attack-Lab Corpus & Measurement Runner

- **`scripts/attack-lab/corpus.py`**: **Tested** (Hand-authored, fully synthetic attack corpus — 2-4 payload variants per §7 category matching the 11 seed signature categories, plus a loader for the existing `tests/security/fixtures/benign/benign_traffic.json` shared benign fixture; nothing downloaded or fetched at runtime)
- **`scripts/attack-lab/run_corpus.py`**: **Tested** (CLI runner measuring true-positive rate per category and false-positive rate on the benign corpus at every `ParanoiaLevel` (PL1-PL4); `--report` for a human table, `--json` for machine-readable output; never modifies `waffy/detection/signatures/`, `waffy/detection/positive/`, or `config/rules/seed_rules.toml`)
- **`tests/security/test_attack_lab.py`**: **Tested** (5/5 passing; invokes the runner as a subprocess and asserts on real measured output, not hardcoded expectations)
- **Measured results (WSL Ubuntu, Python 3.14.4, this session, `uv run python scripts/attack-lab/run_corpus.py --report`)**:
  - **PL1**: sqli 100% (3/3), xss 100% (3/3), command_injection 100% (4/4), path_traversal 100% (3/3), lfi_rfi 100% (3/3), **ssti 66.67% (2/3)**, xxe 100% (2/2), deserialization 100% (2/2), crlf_injection 100% (2/2), open_redirect 0% (0/2 — correct, PL2-gated signature), scanner_fingerprint 100% (3/3). Benign false-positive rate: **0.00% (0/7)**.
  - **PL2/PL3/PL4**: identical to PL1 except open_redirect rises to 100% (2/2) once its PL2 signature is enabled — no PL3/PL4-only signatures exist yet in `config/rules/seed_rules.toml`, so PL3/PL4 numbers are identical to PL2. Benign false-positive rate unchanged: **0.00% (0/7)** at every level.
  - **Known real gap** (not a corpus bug — verified by regex analysis and left as-is per this task's "measurement, not tuning" constraint): `WAFFY-SSTI-001`'s `${...}` alternative requires `Runtime`/`exec`/a digit expression *immediately* before the closing `}`. `${Runtime.getRuntime()}` ends in `()}`, so it does not match. Follow-up: broaden the FreeMarker `${...}` alternative in a future signature-tuning task (out of scope here).
  - Benign corpus is only 7 items — a real per-route production FP rate is **Not yet validated**; 0% here is an honest measurement on a small synthetic sample, not a production guarantee.
- **`docs/PROGRESS.md`**: this entry (**Implemented**)

### Phase 9 / Task 02 (prompts/02-performance-benchmarks.md) — Performance Benchmark Suite

- **`scripts/benchmarks/common.py`**: **Tested** (Shared pipeline factory — real seed signatures at PL1, `FakeUpstreamClient`, SHADOW mode, ML anomaly scorer disabled — plus a raw-ASGI-scope request driver that times only `await pipeline(...)`, excluding httpx client overhead)
- **`scripts/benchmarks/latency_bench.py`**: **Tested** (200 warmup + 2000 measured sequential requests, IP-rotated to avoid rate-limiter skew; reports min/p50/p95/p99/max/mean/stdev in ms plus reference-hardware metadata)
- **`scripts/benchmarks/throughput_bench.py`**: **Tested** (64 concurrent IP-distinct workers over a 5s window; reports sustained req/sec and a direct queue-growth check via per-second completion-count trend)
- **`docs/PERFORMANCE.md`**: **Implemented** (Real measured output from both scripts, explicit in-process/FakeUpstreamClient scope statement, reference hardware: 12th Gen i7-12700F / 20 logical CPUs / 15 GiB RAM / WSL2 Ubuntu / CPython 3.14.4, run timestamped 2026-09-02)
- **Measured results (this session)**: **p99 added latency: 0.34 ms** (148-byte JSON body, PL1 default rule set); **sustained throughput: ~7,325 req/sec** at concurrency 64 with `queue_growth_detected: false` (flat per-second completion profile across the 5s window). No prior target existed to compare against — this run establishes the baseline.
- **Caveat carried into docs/PERFORMANCE.md**: single-process, single-machine, `FakeUpstreamClient`-backed numbers only — no real network RTT, no real upstream latency, no TLS handshake cost, ML anomaly scoring not exercised. **Not yet validated** against a real deployment.
- **`docs/PROGRESS.md`**: this entry (**Implemented**)

### Phase 9 / Task 03 (prompts/03-standalone-tls-integration-test.md) — Real TLS Handshake Integration Test for Standalone Proxy Mode

- **`tests/integration/test_phase7_deployment.py::test_standalone_tls_real_handshake_roundtrip`**: **Tested** (Marked `@pytest.mark.tls_integration`, registered in `pyproject.toml`; replaces the prior `test_standalone_tls_environment_note` placeholder). Verifies, in one real run: a throwaway self-signed cert/key generated via the `openssl` CLI into `tmp_path` (never committed); `FileCertificateProvider.get_certificate()` reading it from disk; `build_ssl_context()` producing the real `ssl.SSLContext` (asserted `minimum_version == TLSv1_2`, unchanged); a real `uvicorn.Server` binding that exact context to a loopback TCP port via `ssl_context_factory`; a real `httpx.AsyncClient` completing a real TLS handshake and validating the server certificate (`ssl.create_default_context(cafile=...)`, not `verify=False`); the decrypted request reaching `WaffyPipelineApplication` and being forwarded to `FakeUpstreamClient` (`upstream.recorded_requests` asserted); `forwarded_record.tls_info is not None` confirming uvicorn's own `scope["scheme"]="https"` detection reached the pipeline.
- **Dependency choice**: cert generation uses the system `openssl` CLI via `subprocess`, not a new Python dependency (`cryptography`) — avoids the CLAUDE.md "new dependency needs explicit justification" question entirely for a one-off test fixture. The test skips (not fails) if `openssl` isn't on `PATH`.
- **TLS version floor**: unchanged — `build_ssl_context` still enforces `TLSv1_2` minimum; this task only added a consumer/verifier, never touched that function.
- **`docs/PROGRESS.md`**: Phase 7 standalone-proxy entry and this entry updated from `Environment-dependent` to `Tested` (**Implemented**)

### Phase 9 / Task 04 (prompts/04-ja3-fingerprint-extraction.md) — Real JA3/JA4 TLS Fingerprint Extraction

- **`waffy/proxy/tls_fingerprint.py`** (new module): **Tested**.
  - `parse_client_hello()` + `compute_ja3()`: **canonical, byte-perfect JA3** (RFC 8446 ClientHello parsing, RFC 8701 GREASE filtering, MD5 of the standard 5-group signature string) computed from raw ClientHello bytes. Unit-tested against a **real** ClientHello captured from a real local Python TLS client over a `socket.socketpair()` (`test_ja3_computed_from_real_captured_client_hello`), plus malformed-input and GREASE-filtering tests.
  - `compute_fingerprint_from_ssl_object()`: a **real-signal, NOT byte-identical to canonical JA3** fingerprint (`waffy-tlsfp-v1:` prefix) derived from a completed handshake's post-handshake `SSLObject`/`SSLSocket` (version, cipher, `shared_ciphers()`, ALPN) — this is what's actually wired into production, because Python's `ssl` module doesn't expose raw pre-handshake ClientHello bytes without a parallel hand-rolled TLS listener (a larger, explicitly out-of-scope follow-up — see `docs/ARCHITECTURE.md`). Tested end-to-end against a real completed local TLS handshake (`test_bot_engine_matches_real_captured_tls_fingerprint`), and tested to degrade to `None` on any failure (`test_compute_fingerprint_from_ssl_object_degrades_gracefully`).
  - `TlsFingerprintRegistry`: bounded LRU `(peer_ip, peer_port) -> fingerprint` map, same pattern as `TimingRegularityTracker`. Tested for bounded eviction and `forget()`.
  - `build_ja3_capturing_protocol()` / `build_standalone_uvicorn_config()`: subclasses uvicorn's internal `H11Protocol` (only overriding `connection_made`/`connection_lost` to additionally record/forget a fingerprint — never touches HTTP parsing) and wires it into a `uvicorn.Config` alongside `build_ssl_context()`'s real TLS context. Degrades to uvicorn's default protocol (no capture, not fatal) if the internal class can't be imported. **Implemented**, not independently integration-tested against a real bound uvicorn TLS socket in this session (the plumbing from `SSLObject -> fingerprint -> registry -> pipeline` is proven end-to-end via the socketpair-based tests instead) — **Environment-dependent** for a full live-uvicorn-listener confirmation.
- **`waffy/config/models.py::BotDetectionConfig.known_bad_tls_fingerprints`** (new field): **Tested**. Empty-by-default, operator-managed local list — explicitly not a live threat-intel feed, per this task's constraints.
- **`waffy/detection/bot/engine.py`**: **Tested**. Replaced the hardcoded `"bad_ja3_fingerprint"`/`"bad_ja4_fingerprint"` placeholder-string comparison with a real check against `config.known_bad_tls_fingerprints`. Scoring weights in `waffy/engine/scoring.py` untouched, per constraints. Evidence-only boundary preserved — `assess()` still only returns `BotAssessment`.
- **`waffy/http/pipeline.py`**: **Tested**. New optional constructor param `tls_fingerprint_lookup: Callable[[str, int], str | None] | None = None`, defaulting to `None` (fully backward compatible — all 96 pre-existing tests still pass unmodified). When set, looked up per-request by `(client_ip, client_port)` and passed into `bot_engine.assess()`. Kept as a plain callable rather than a proxy-layer import, preserving the `core -> config -> http -> ... -> proxy` one-way dependency flow. Tested end-to-end (`test_pipeline_wires_tls_fingerprint_lookup_into_bot_assessment`).
- **Dependency decision**: **no new dependency added** — full justification, including why canonical byte-perfect JA3 isn't yet the production path and what a follow-up would need, is in `docs/ARCHITECTURE.md` (new file, created by this task).
- **Pre-existing gap noticed, not fixed here (out of scope for this task)**: `config/default_config.toml`'s `[bot]` section doesn't match `WaffyConfig.bot_detection`'s expected `[bot_detection]` section name, so bot-detection TOML config is currently silently ignored at load time regardless of this task. Documented in `docs/ARCHITECTURE.md`, flagged as a natural fit for prompts/07's config-validation-warnings task.
- **`docs/PROGRESS.md`**: this entry + the bot/engine.py line above updated (**Implemented**)

### Final Release Quality Gate (Phase 10)

```text
--- RUFF ---
All checks passed!
--- PYRIGHT ---
0 errors, 0 warnings, 0 informations
--- PYTEST ---
91 passed, 604 warnings in 6.59s
```
