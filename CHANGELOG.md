# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project intends to adhere to [Semantic Versioning](https://semver.org/)
once it starts tagging releases (see "Versioning policy" below).

Dates below are taken directly from git commit history where available.
Work predating a specific commit (e.g. within a single large session) is
grouped under that session's last commit date rather than guessed at a
finer granularity — see each entry.

## [Unreleased]

Work from the "Complete-the-Project" master session, closing gaps between
"spec-complete, functionally tested" and "deployable, industry-standard
open source project."

### Added

- **SSRF signature detection** (`ssrf` category): four seed rules covering
  cloud metadata endpoints, loopback/RFC1918 targets behind a URL scheme,
  `gopher://`/`dict://` schemes, and a paranoia-level-2-gated parameter-name
  heuristic. Required a small additive signature-engine change
  (`SignatureDefinition.field_name_pattern`) to combine a parameter-name
  signal with a value signal.
- **Byte-accurate canonical JA3 fingerprinting** for standalone TLS mode via
  a pre-TLS-accept `socket.MSG_PEEK` stage (`PreAcceptTlsServer`), with a
  `tls.ja3_capture_mode` config toggle (`clienthello_peek` / `post_handshake`
  / `disabled`) to revert without a code change.
- **Property-based (Hypothesis) fuzz test coverage** for HTTP parsing and
  normalization (dev-only dependency) — found and fixed a real bug (see
  Fixed, below).
- Explicit **GraphQL/WebSocket scope-boundary documentation**
  (`docs/ARCHITECTURE.md`) — WebSocket traffic is actively denied (not
  merely unprotected) in every deployment mode; GraphQL is only protected
  incidentally, as ordinary JSON body text.
- Windows/WSL development prerequisite documentation (`README.md`,
  `docs/DEPLOYMENT.md`, `waffy/ipc/server.py`).
- `LICENSE` (MIT), `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, root-level
  `SECURITY.md` (vulnerability disclosure policy), and this `CHANGELOG.md`.
- `docs/SECURITY.md` (waffy's own threat model / security posture) —
  previously linked from `README.md` but never actually created; written
  from `CLAUDE.md`'s architecture rules and already-documented findings.
- **GitHub Actions CI** (`.github/workflows/ci.yml`): ruff, pyright, and
  pytest (with coverage) on `ubuntu-latest` across a Python 3.12/3.13
  matrix, plus a `dependency-audit` job running `pip-audit`.
- **`.github/dependabot.yml`**: weekly update PRs for the `pip` and
  `github-actions` ecosystems.
- **Test coverage measurement**: `pytest-cov` (dev-only), `[tool.coverage.*]`
  in `pyproject.toml` with an 80% CI-enforced floor. Measured 82% at the
  time of this step (see `docs/PROGRESS.md` for the current number, which
  moved slightly once the new Docker entrypoint scripts below were added).
- **Dockerfile + docker-compose.yml**: a multi-stage, non-root evaluation
  stack (waffy-core + waffy-api + a trivial demo upstream app), verified
  end-to-end against a real Docker daemon this session, including a real
  SQL-injection payload producing a genuine, logged detection while still
  respecting `SHADOW` mode. New `waffy/runtime/serve_core.py` /
  `serve_api.py` entrypoints, explicitly scoped as Docker/eval-only (the
  production `core_daemon.py` still does not bind a real listener).
- README badges (CI, license, Python version, coverage), a corrected
  Quickstart config example, a runnable Docker "try it" snippet, and links
  to `CONTRIBUTING.md`/`CODE_OF_CONDUCT.md`/`SECURITY.md`/`CHANGELOG.md`.

### Fixed

- `waffy/http/body.py::parse_multipart_metadata()` raised an unhandled
  `ValueError` (not the documented `RequestMalformedError`) for a
  Content-Type header containing a bare CR/LF, found by the new
  Hypothesis fuzz tests. Root cause was a dead-code
  `email.message.EmailMessage()` construction whose result was never read;
  deleted rather than patched around.
- Stale documentation cross-references claiming the systemd unit file "is
  built in Phase 9" — `deploy/systemd/waffy-core.service` already existed;
  both mentions now point at the real file.
- README's Quickstart told operators to set a flat `enforcement_mode` key
  in `config.toml` — the real schema is a nested `[enforcement]` section
  with lowercase values (`"shadow"`/`"assisted"`/`"active"`).

### Known issues found this session (not fixed — tracked openly)

- **`WaffyPipelineApplication`'s observability outputs are wired to
  nothing live.** The `event_sink` parameter and
  `IpcStateStore.record_event`/`record_assessment` have no caller anywhere
  connecting them to real pipeline traffic — confirmed by curling the
  management API's `/api/v1/events`/`/api/v1/requests` endpoints
  immediately after a real, logged SQLi detection in the Docker stack and
  finding both empty. This means those feeds and any configured SIEM
  `EventSink` currently receive nothing from a live-running pipeline.
- The `ml` optional-dependency group is not actually optional at import
  time — `waffy/http/pipeline.py` imports through to `joblib`
  unconditionally at module scope.
- `tests/integration/test_task13b_preaccept_ja3.py::test_capture_mode_post_handshake_skips_peek_uses_ssl_object_signal`
  is flaky at a measured ~6.7% (1/15) failure rate — a real race in the
  `capture_mode="post_handshake"` fallback path, not host-load noise.
- Throughput is measured ~10% below the original baseline (see Performance,
  below), attributed to the larger PL1 rule count from the new SSRF
  category.

### Performance

- Re-measured latency/throughput on the same reference hardware as the
  original 2026-09-02 baseline: no latency regression (p99 ~0.29-0.31ms vs.
  0.34ms baseline); a real, measured ~10% throughput decrease (~6,565 vs.
  ~7,325 req/sec), most plausibly attributable to the larger PL1 rule count
  from the new SSRF category — reported honestly per `docs/PERFORMANCE.md`,
  not tuned away.

## [0.1.0] - 2026-09-03

Initial feature-complete implementation. Not yet tagged in git as of this
writing — `pyproject.toml`'s version has stayed at `0.1.0` throughout all
of the work below; see "Versioning policy" for what happens next.

This entry backfills the full history from the initial scaffold
(2026-08-31) through the last commit of the second hardening/correctness
batch (2026-09-03, `prompts/13`) — see `docs/PROGRESS.md` for the complete,
per-deliverable, honesty-labeled breakdown; this changelog entry is a
summary, not a replacement for it.

### Added

- **Core engine** (Phases 1-8): Pydantic v2 config/domain models; HTTP
  parsing, normalization, and anti-evasion (smuggling/desync rejection,
  decompression-bomb guard, XXE-safe XML parsing); signature-based
  detection engine (SQLi, XSS, command injection, path traversal, LFI/RFI,
  SSTI, XXE, deserialization, CRLF injection, open redirect, scanner
  fingerprints) with paranoia-level filtering and a per-request time
  budget; positive-security route constraints; an evidence-only ML
  anomaly-scoring layer (Isolation Forest, canonical feature extractor);
  additive scoring and mode-aware decision engine with the Evidence-
  Maturity Invariant; a single authorized enforcement execution point with
  a 9-stage action-validation chain; rate limiting, bot detection, and
  session/cookie/CSRF/credential-stuffing checks; three deployment modes
  (standalone TLS reverse proxy, plaintext-behind-existing-terminator
  proxy, ASGI middleware) sharing one pipeline; a Unix-domain-socket IPC
  layer between `waffy-core` and a separate management API/control-panel
  process; Prometheus metrics and RFC 5424 syslog SIEM integration.
- **Hardening batch 1** (`prompts/01`-`07`): synthetic attack-lab corpus and
  measurement runner; performance benchmark suite (`docs/PERFORMANCE.md`);
  a real TLS handshake integration test; real JA3/JA4 TLS fingerprint
  extraction from a completed handshake; an audit and fix of enforcement-
  state persistence (`SqliteRuleStore`, opt-in); an HTTP/2 desync/evasion
  investigation (finding: no HTTP/2 code path exists in this stack at all);
  startup-time config-validation warnings for silently-disabled features.
- **Hardening batch 2** (`prompts/08`-`13`): wired `CredentialStuffingDetector`
  and `CsrfProtector` into the live request pipeline as evidence producers
  (previously implemented but never called); closed a real SSTI signature
  gap (66.67% → 100% true-positive rate); added a human-approval promotion
  gate (`ModelGovernanceService`) between a newly trained anomaly baseline
  and it going live; fixed a `[bot]`/`bot_detection` config section-name
  mismatch that silently discarded bot-detection TOML config (and flagged,
  not fixed, an identical bug in `[ratelimit]`/`rate_limiting`); documented
  `SqliteRuleStore`'s exact persistence coverage; investigated byte-accurate
  canonical JA3 via raw ClientHello capture and stopped with a documented
  architectural blocker (later resolved — see `[Unreleased]` above).

### Known limitations at this milestone

See `docs/PROGRESS.md`'s "Overall State" summary for the complete, current
list — as of this entry: `SqliteRuleStore` persistence opt-in; production
TLS fingerprinting not yet byte-identical to canonical JA3 (resolved in
`[Unreleased]`); HTTP/2 unsupported by the ASGI server stack; the
`[ratelimit]`/`rate_limiting` config mismatch and several TOML sections
with no config surface at all; `waffy/runtime/__main__.py` is a
startup-checks-only entrypoint, not the full daemon; no `/panel/models`
control-panel page for model governance yet.

## Versioning policy

This project has not yet made a tagged release — `pyproject.toml`'s
`version` field has stayed at `0.1.0` through all development so far.
Going forward: [Semantic Versioning](https://semver.org/) (`MAJOR.MINOR.PATCH`).
Before `1.0.0`, breaking changes may land in a `0.x` minor bump rather than
strictly requiring a major version, consistent with SemVer's own guidance
for initial development. Tagging an actual git release is a deliberate,
operator-approved step (see `docs/PROGRESS.md`'s Phase D entry) — this file
is updated in every PR that changes user-facing behavior, per
`CONTRIBUTING.md`, whether or not that change has shipped in a tagged
release yet.
