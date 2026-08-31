# waffy — MASTER IMPLEMENTATION SPECIFICATION

## 1. PURPOSE

waffy is a standalone, per-host Web Application Firewall. It is deployed on
an individual machine, in front of (or embedded with) one or more web
applications/APIs running on that same machine, and inspects real,
decrypted HTTP(S) request and response content to detect and stop
application-layer attacks that a network-layer firewall structurally cannot
see: SQL injection, cross-site scripting (XSS), remote/local file
inclusion, OS command injection, server-side template injection (SSTI),
XML external entity (XXE) injection, insecure deserialization, path
traversal, server-side request forgery (SSRF) via request content, HTTP
request smuggling/desync attempts, credential stuffing and brute force,
malicious/automated bot traffic, and known-CVE exploitation attempts
(virtual patching). It is the payload-inspection counterpart to a
network-layer/flow-based firewall like pirewall, without depending on one.

## 2. DEPLOYMENT MODEL

waffy runs as a **reverse proxy** on the host: it terminates (or receives
already-terminated) HTTP(S) connections, inspects each request, decides an
action, and — if allowed — forwards the request to the real upstream
application listening on a different local port or socket, then inspects
and (optionally) forwards the response back to the client. Three concrete
deployment modes, all built on the same core engine:

- **Standalone TLS-terminating reverse proxy** — waffy listens on
  443/80, owns the TLS certificate, forwards decrypted plaintext HTTP to
  the upstream app over loopback/Unix socket. Simplest to reason about;
  recommended default.
- **Plaintext reverse proxy behind existing TLS termination** — waffy
  listens on a local port/socket, receives already-decrypted HTTP from an
  upstream TLS terminator (e.g. the host's existing nginx/load balancer)
  configured to proxy to waffy instead of the app directly. No cert
  management needed in this mode.
- **Embedded ASGI middleware** — for Python (ASGI/WSGI) applications only,
  waffy's detection/decision core is importable as middleware inserted
  directly into the app's request pipeline, skipping the separate proxy
  hop. Must reuse the exact same detection/decision code as the proxy
  modes — no parallel implementation.

All three share one engine; only the transport/edge layer differs. Document
this sharing explicitly in `docs/ARCHITECTURE.md`.

## 3. CORE PIPELINE

```
Client → [Transport: TLS/plaintext listener] → [HTTP parse + normalize]
       → [Detection: signatures + positive-security + rate/session/bot]
       → [Scoring: additive anomaly score + ML evidence]
       → [Decision: score+evidence → Action, mode-aware (SHADOW/ASSISTED/ACTIVE)]
       → [Enforcement: ALLOW passthrough | LOG | CHALLENGE | RATE_LIMIT | BLOCK]
       → [Upstream app] → [Response: optional response-side checks] → Client
```

Every stage produces a typed, inspectable evidence/record object. No stage
skips ahead — a request that should be blocked still flows through
scoring/decision in `SHADOW` mode, it just isn't enforced.

## 4. TRANSPORT & HTTP PARSING

- Support HTTP/1.1 fully (including chunked transfer-encoding, keep-alive,
  pipelining awareness) and HTTP/2 (via the ASGI server's HTTP/2 support or
  an explicit h2-based implementation — pick one, document it).
  WebSocket upgrade requests are detected and, by default, passed through
  after header-level inspection only (body framing is opaque to HTTP
  parsing) — document this as a scope boundary, not a silent gap.
- Parse and reject **malformed/ambiguous requests outright** before they
  reach detection: mismatched or duplicate `Content-Length`, both
  `Content-Length` and `Transfer-Encoding` present (classic smuggling
  vector), invalid chunked encoding, headers exceeding configured
  size/count limits, request line exceeding configured length. This is a
  distinct `RequestMalformed` outcome, logged, and — even in `SHADOW` mode —
  rejected at the transport layer, because passing an ambiguous request
  through for "shadow observation" isn't meaningful; document why this one
  category is exempt from SHADOW pass-through.
- Body handling: buffer up to a configured max body size (streaming past
  that limit is rejected, not silently truncated-and-inspected), decompress
  supported `Content-Encoding` values (gzip, deflate, br if the library is
  available) with a decompression-bomb guard (max decompressed size,
  max compression ratio), then parse by declared `Content-Type`: JSON, URL-
  encoded form, multipart/form-data (including file part metadata —
  filename, declared content-type, size — without necessarily scanning file
  *content* in v1; document that boundary), and XML (with XXE-safe parsing
  — external entity resolution disabled unconditionally at the parser
  level, not just detected as a signature).

## 5. NORMALIZATION (ANTI-EVASION)

Before any signature or positive-security check runs, request components
(URL path, query string, header values relevant to matching, body field
values) are normalized through a documented, ordered pipeline so an
attacker can't evade a pattern with encoding tricks: percent-decoding
(with a cap on decode passes to avoid infinite/adversarial nesting — decode
until stable or N passes, whichever first, and flag "excessive encoding
layers" itself as a weak anomaly signal), `+`/space normalization in query
strings, Unicode NFKC normalization, case normalization for
case-insensitive checks (keep original case available separately for
checks that need it), path normalization (collapse `..`/`.`/duplicate
slashes for path-traversal checks *without* mutating the actual path used
to route the request — normalization is for detection, never silently
rewrites what gets forwarded upstream unless a rule explicitly says so).
Every normalization step is unit-testable in isolation against a table of
known evasion techniques (double encoding, mixed encoding, overlong UTF-8,
null-byte injection, case variation).

## 6. DOMAIN MODELS (Pydantic v2, crossing any boundary)

`HttpRequestRecord` (method, path, query params, headers, cookies, parsed
body summary, client address, TLS info if available, raw size, timestamp),
`Signature` (id, category, pattern, paranoia_level, target fields, score
weight, description, references e.g. CVE/CWE id), `SignatureMatch`
(signature id, matched field, matched substring — truncated/redacted for
logs per §17 — offset), `AnomalyEvidence` (ML/statistical score, feature
vector version, model id/version), `PositiveSecurityViolation` (route id,
violated constraint), `RateLimitState`, `BotAssessment` (score, matched
heuristics), `RequestAssessment` (aggregates all evidence for one request:
signature matches, anomaly evidence, positive-security violations, bot
assessment, rate-limit state, total anomaly score), `Decision` (action,
mode, reasons, evidence refs), `EnforcementAction` (ALLOW, LOG, CHALLENGE,
RATE_LIMIT, BLOCK), `BanEntry`/`CandidateBan` (target IP/CIDR or session
key, scope, reason, evidence refs, created_at, expires_at, status),
`AllowlistEntry` (target, reason, created_by, created_at — same concept as
pirewall's, admin-declared, outranks everything), `VirtualPatchRule`
(targeted CVE/vuln id, match conditions, action, expiry), `SecurityEvent`
(type, severity, timestamp, source IP, request summary, decision,
correlation id), `ModelMetadata`. Strict validation on every field
(bounded strings/ints, valid IP/CIDR types, timezone-aware timestamps).

## 7. DETECTION — SIGNATURE ENGINE

- A rule/signature engine broadly compatible in *spirit* with the OWASP
  Core Rule Set (CRS): rules are additive-scoring, not first-match-block —
  a request accumulates an anomaly score across every matching signature,
  and the *decision* layer (§10), not the detection layer, decides what
  score maps to what action. Ship a **seed rule set** (in
  `config/rules/`, versioned, human-editable — plain structured text/TOML/
  YAML, your choice, documented) covering at minimum: SQL injection
  (union-based, boolean-blind, time-blind, error-based markers, common
  DBMS-specific syntax), XSS (script tags, event handlers, javascript:
  URIs, common encoding evasions), OS command injection (shell
  metacharacters, common command names in unexpected contexts), path
  traversal, LFI/RFI markers, SSTI markers (common template-engine syntax
  across Jinja2/Twig/Freemarker/etc.), XXE markers (as a secondary signal —
  the parser-level disable in §4 is the real control), insecure
  deserialization markers (e.g. Java/PHP/Python pickle magic
  bytes/gadget-chain hints in bodies), CRLF/header-injection attempts,
  open-redirect patterns, and a "known bad" list of scanner/exploit-tool
  user-agents and request fingerprints (sqlmap, nikto, nuclei, common
  Metasploit HTTP handlers) as a separate, lower-weight category (a
  scanner UA alone shouldn't BLOCK, it should raise score).
- **Paranoia levels**, matching CRS convention: 1 (low false-positive,
  default/shipped-enabled), 2–4 (progressively more aggressive/more
  false-positive-prone, opt-in via config). Every signature declares which
  level it belongs to.
- Rules are data, loaded at startup (and hot-reloadable via an explicit
  admin action, never silently on a filesystem watch — an attacker
  shouldn't be able to influence rule reload timing). No signature logic
  is hardcoded Python string matching scattered through the codebase —
  one rule engine, data-driven.
- Every regex-based signature is checked at load time for a documented
  complexity budget (see `CLAUDE.md`'s backtracking rule) and the engine
  enforces a per-request total matching time budget; exceeding it aborts
  remaining signature checks for that request, logs a `RULE_ENGINE_BUDGET_EXCEEDED`
  event, and the request still proceeds through whatever evidence was
  already collected — never hangs the request indefinitely.

## 8. DETECTION — POSITIVE SECURITY MODEL

- Optional, per-route configuration (`config/routes/` or embedded in the
  route's OpenAPI spec if the operator supplies one) declaring: allowed
  HTTP methods, allowed `Content-Type`s, parameter names/types/max
  lengths/regex constraints, whether unknown parameters are rejected or
  merely flagged. A route with no positive-security config runs
  signature-only (negative security) checks — positive security is
  additive protection, never a hard requirement to deploy waffy at all.
- Violations produce `PositiveSecurityViolation` evidence, scored and fed
  into the same decision pipeline as signature matches — not a separate
  automatic block path.

## 9. DETECTION — RATE LIMITING & DoS

- Token-bucket or sliding-window limiters, configurable per: source IP,
  per authenticated session/user (once identified), per route/endpoint,
  and globally per-instance as a last-resort circuit breaker.
- Because waffy sits **inline** (unlike pirewall's out-of-band flow
  observation), it can directly enforce connection/request timeouts, max
  concurrent connections per source, max request header/body size, and
  slow-request detection (minimum bytes/second on request body upload) —
  implement these as first-class inline controls, not just detection
  signals, since inline placement makes direct enforcement both possible
  and necessary (a slow-POST/slowloris-style attacker held open
  indefinitely is a resource-exhaustion risk to waffy itself, not just
  something to score).
- Rate-limit trips are `RequestAssessment` evidence like anything else and
  flow through the same decision layer — a trip doesn't bypass decision to
  self-enforce, except for the hard connection/resource-protection timeouts
  above, which are transport-layer safety limits, not "detections", and are
  documented as such.

## 10. DETECTION — BOT & SESSION PROTECTION

- Bot heuristics: User-Agent analysis against known-bad and known-good
  (search engine) lists, header-order/header-set fingerprinting, TLS
  ClientHello fingerprinting (JA3/JA4) when TLS info is available from the
  termination layer, request-timing regularity (coefficient-of-variation
  style check, same statistical shape as pirewall's `TEMPORAL_PATTERN` —
  reuse the concept, not the code), and honeypot-link detection (an
  invisible link only a scraper would follow). Combine into a
  `BotAssessment` score, never a hard automatic block by itself.
- Session protection: CSRF token generation/validation helpers (for apps
  that opt in via the embedded-middleware mode, or header-based validation
  in proxy mode), enforcement of `Secure`/`HttpOnly`/`SameSite` cookie
  attributes on responses waffy proxies (configurable — rewrite missing
  attributes rather than reject, documented as a distinct, lower-risk
  action from blocking), and credential-stuffing detection (failed-login
  velocity per source and per targeted account, if the operator configures
  which route/response-pattern indicates a login failure).

## 11. ML / ANOMALY SCORING LAYER

- One canonical feature extractor (`waffy/detection/anomaly/features.py` or
  equivalent) producing a versioned feature vector from an
  `HttpRequestRecord` + accumulated per-route/per-source baseline stats:
  request length, parameter count, per-parameter length/entropy, path
  segment count/depth, header count, unusual header presence, method/
  content-type rarity for the route, character-class ratios (alnum vs
  special vs encoded). Same extractor used for both offline baseline-
  building and runtime scoring — never two implementations.
- An unsupervised model (Isolation Forest or equivalent, matching
  pirewall's stack choice for consistency) trained per-route (or per-route-
  class if traffic is too sparse) during an explicit **learning/baseline
  mode**, distinct from `SHADOW` enforcement mode — learning mode exists to
  build the baseline from real observed traffic before the model is trusted
  for scoring at all. Document the minimum sample size before a route's
  model is considered usable; routes below it fall back to signature-only
  scoring, never a half-trained model silently contributing score.
- Model output is `AnomalyEvidence`, one contribution to the total score —
  never a standalone decision path. Model artifacts are versioned
  (`ModelMetadata`) and reloadable without a full process restart.

## 12. SCORING & DECISION ENGINE

- Additive scoring: every piece of evidence (signature matches by paranoia
  level, positive-security violations, bot score, anomaly score,
  known-scanner-fingerprint hits) contributes a weighted amount to one
  `RequestAssessment.total_score`. Weights live in config, not code.
- Threat-level thresholds (LOW/MEDIUM/HIGH/CRITICAL, matching pirewall's
  naming for consistency) map to a base action via a decision table, but —
  same principle as pirewall's B3 evidence-maturity gate — a `BLOCK` (or
  in waffy's case, `BLOCK`/`CHALLENGE` at the top of the ladder) requires
  evidence that is either (a) a signature match at paranoia level 1 with a
  category historically low-false-positive (e.g. a clear SQLi UNION
  pattern), or (b) multiple independent evidence categories corroborating
  (e.g. signature match *and* elevated anomaly score *and* bot signal), or
  (c) the same elevated-but-ambiguous reading recurring from the same
  source across N consecutive requests. A single weak/ambiguous signal
  alone caps at `LOG`/`CHALLENGE`, never `BLOCK`, regardless of raw score —
  implement this as an explicit, named, tested invariant, not an emergent
  property of tuned weights.
- `EnforcementMode` — `SHADOW`, `ASSISTED`, `ACTIVE` — identical concept and
  default (`SHADOW`) to pirewall's A1: in `SHADOW`, the full pipeline runs
  and every decision is logged as "would have happened" but nothing is
  enforced against real traffic. In `ASSISTED`, low-risk actions (LOG,
  CHALLENGE) auto-apply; `BLOCK`/`RATE_LIMIT` above a configurable
  threshold go to a `PENDING_APPROVAL` queue reviewable in the control
  panel. In `ACTIVE`, everything auto-applies per the decision table.

## 13. ENFORCEMENT ACTIONS

- `ALLOW` — forward to upstream unmodified.
- `LOG` — forward to upstream, record a `SecurityEvent`, no client-visible
  change.
- `CHALLENGE` — respond to the client with a challenge (JS proof-of-work
  challenge and/or a pluggable CAPTCHA provider interface) instead of
  forwarding; a passed challenge sets a short-lived trust token so the
  client isn't re-challenged every request. `ChallengeVerifier` is a
  Protocol with a real implementation and a `Fake` for tests, per
  `CLAUDE.md`.
- `RATE_LIMIT` — respond with 429 and `Retry-After`, do not forward.
- `BLOCK` — respond with a configurable status (403 by default) and a
  generic, non-information-leaking body (never echo the matched
  payload/signature name back to the client), do not forward.
- Every enforcement action that creates persistent state (a `BanEntry`
  blocking a source for a duration, a `VirtualPatchRule`) is a
  `CandidateBan`/`CandidateRule` that passes the **full validation chain**
  from `CLAUDE.md` before becoming active: schema → network/target
  validity → allowlist → safety (never ban the configured admin/management
  source, never ban 0.0.0.0/0 or an overly broad CIDR the evidence doesn't
  justify) → conflict → duplicate → rate-cap (bounded new-bans per window,
  same concept as pirewall's A3) → expiration → authorization. This exists
  even though most individual `BLOCK` responses are per-request and
  stateless — the validation chain specifically guards *persistent*
  actions (IP bans, virtual patches), which is where a mistake compounds.

## 14. ALLOWLIST & KILL-SWITCH

- `AllowlistEntry` (admin/management source, trusted partner IPs, health-
  check source, etc.) outranks every adaptive decision unconditionally —
  same as pirewall's A2, same validator-chain position (checked before
  safety).
- A kill-switch endpoint/control-panel action — same shape as pirewall's
  A8 — immediately sets `EnforcementMode` to `SHADOW` and transitions every
  currently-active adaptive ban/virtual-patch rule to a removed/expired
  state (the allowlist itself is untouched), logs one summary event plus a
  per-entry audit record, and requires the same authentication as every
  other management action.

## 15. FAIL-SAFE BEHAVIOR

- Default `failure.mode = "fail_open"`: if the core proxy/enforcement
  process crashes, is overloaded past a configured resource limit, or a
  dependency (rule store, model artifacts) fails to load, the process
  either passes traffic straight through unfiltered (if a watchdog/
  supervisor can restart it fast enough that the operator has configured a
  brief fail-open passthrough window) or the deployment fails closed to
  the *operator's own explicit choice* — document both paths and make the
  choice a config field (`failure.mode = "fail_open" | "fail_closed"`),
  same pattern as pirewall's A6, with the same justification: for a
  production website, an outage from an over-zealous or crashed WAF is
  often worse than temporarily unfiltered traffic, but this must be the
  operator's informed choice, not a silent default that surprises them —
  document the trade-off prominently in `docs/DEPLOYMENT.md`.
- A supervisor/watchdog (systemd `Type=notify` + `WatchdogSec=`, same
  mechanism pirewall used) restarts a hung/crashed core process; a
  crash-loop raises a high-severity `SecurityEvent`.

## 16. PROCESS ARCHITECTURE & PRIVILEGE SEPARATION

Two processes, same split concept as pirewall's A4:

- **`waffy-core`** — the request-path proxy: transport, parsing,
  detection, scoring, decision, enforcement. Runs as a dedicated non-root
  user with only the capabilities it needs (binding low ports if in
  standalone TLS mode needs `CAP_NET_BIND_SERVICE`, nothing else — no raw
  sockets, no arbitrary filesystem write outside its own state
  directory).
- **`waffy-api`** — the management API + control panel. A different,
  more restricted non-root user, with **no ability to bind the public
  listener or touch TLS private key material directly**. Talks to
  `waffy-core` over a local Unix domain socket (filesystem-permissioned to
  just these two users) to read state (recent requests/decisions/events/
  bans/rules) and submit only already-authorized actions (allowlist
  changes, approve/reject pending actions, kill-switch, rule reload
  trigger). This must be true at the import-graph level, exactly like
  pirewall's A4 — if `waffy/api/` or `waffy/web/` imports the proxy/
  enforcement modules directly, that's a bug to fix, not a convenience to
  keep.

## 17. LOGGING & PRIVACY

- Structured JSON logs with a correlation id per request. **Redact/truncate
  sensitive values before they're written anywhere**: never log a full
  password/credit-card/authorization-header value even when it's the thing
  that matched a signature — log enough matched context to be useful (field
  name, signature id, a bounded/truncated snippet with the sensitive part
  masked) and no more. Configurable field-name denylist (password, token,
  authorization, cookie by default) whose values are always masked in logs
  regardless of what triggered the log line.
- `SecurityEvent` schema intentionally shaped to be easy to forward to a
  SIEM (see §20) and, loosely, comparable to pirewall's own event shape
  (type, severity, timestamp, source, summary, correlation id) so an
  operator running both tools can correlate them by eye — without waffy
  depending on pirewall's code or schema at all.

## 18. MANAGEMENT API & CONTROL PANEL

- FastAPI-based REST API (`waffy-api` process only), authenticated (token
  or session-based — pick one, document it, never unauthenticated by
  default), restricted to a configured management source
  (IP/CIDR allowlist for the API itself, separate from the WAF's own
  target-site allowlist) — same "don't expose management to the whole
  internet" discipline pirewall used for its Admin PC concept.
- Endpoints at minimum: live/recent request+decision feed, `SecurityEvent`
  list/filter, ban list (list/create/expire/delete), allowlist
  (list/create/delete), virtual-patch rules (list/create/disable),
  enforcement-mode get/set, pending-approval queue (list/approve/reject),
  kill-switch, rule-set reload trigger, per-route positive-security config
  CRUD, health/status.
- A minimal web control panel (server-rendered or a small SPA — your
  choice, document it) surfacing the above: dashboard (requests/sec,
  score distribution, top triggered signatures, mode banner), live event
  stream, ban/allowlist management, pending-approval queue with one-click
  approve/reject, kill-switch button, per-route config editor.

## 19. INTEGRATION & OBSERVABILITY

- **SIEM**: forward `SecurityEvent`s to Wazuh (or any syslog/JSON-over-
  network sink) via a configurable output — same integration point
  pirewall already uses, so an operator running both tools points them at
  one Wazuh instance. Implemented as a pluggable `EventSink` Protocol
  (syslog implementation + a `Fake` for tests), not a hardcoded Wazuh-only
  path, so other sinks can be added later without a rewrite.
- **Metrics**: expose a metrics endpoint (Prometheus-format and/or Netdata-
  compatible, matching pirewall's Netdata usage) covering requests/sec by
  outcome, score distribution, per-signature hit counts, rate-limit trips,
  ban-list size, rule-engine budget-exceeded count, process resource usage.
- **Health checks**: liveness/readiness endpoints for both processes,
  usable by systemd's watchdog and by any external monitoring.

## 20. TECHNOLOGY STACK

Python 3.12+, `uv`-managed, Pydantic v2, FastAPI + an ASGI server (uvicorn
or hypercorn — pick one, document HTTP/2 support implications), `httpx` for
the upstream client, `pytest` + `ruff` + `pyright --strict`, scikit-learn
for the anomaly model. A dedicated pattern-matching approach for the rule
engine — either Python's `re`/`regex` module with the complexity guards
from §7, or a bound hyperscan/re2 library if you determine pure-Python
regex won't meet the performance budget (§21) — decide and document the
choice and its trade-offs in `docs/ARCHITECTURE.md`, don't silently default
without stating why.

## 21. PERFORMANCE

waffy sits inline with every request to a real application — unlike
pirewall's out-of-band observation, added latency here is directly user-
visible. State an explicit, tested latency budget in `docs/PERFORMANCE.md`
(e.g. "p99 added latency under N ms for a request under M KB against the
default paranoia-1 rule set, measured on reference hardware") and a
throughput budget (requests/sec sustained without queueing growth). Back
every number with an actual benchmark script and actual measured output —
never an estimated/assumed number, consistent with the labeling-honesty
rule.

## 22. TESTING

- **Unit tests**: every parser/normalizer against a table of known evasion
  techniques; every signature against both a matching and a deliberately-
  similar-but-benign payload (false-positive check, not just true-positive);
  scoring/decision logic including the evidence-maturity invariant from
  §12; validation chain ordering and each stage's rejection behavior;
  rate limiter correctness (window boundaries, concurrent sources).
- **Integration tests**: full pipeline through a `FakeUpstreamClient` —
  real transport parsing, real detection, real scoring, real decision,
  fake forwarding — for representative attack and benign traffic.
- **Security/attack-lab tests**: a self-contained, synthetic (not
  downloaded-at-test-time, not pulled from a live internet source at
  runtime) corpus of attack payloads per category from §7, checked for
  both detection (true positive) and, separately, a benign-traffic corpus
  checked for false-positive rate at each paranoia level — report the
  actual measured false-positive rate, don't assume zero.
- Protocol/Fake pattern for every environment-dependent component per
  `CLAUDE.md` — no test may require a real socket bind, a real upstream
  server, or a real TLS certificate to run in CI.

## 23. REPOSITORY STRUCTURE (create in Phase 1, exact tree)

```
waffy/
  waffy/
    core/            # enums, exceptions, domain models (Pydantic v2)
    config/           # config loader + Pydantic settings models
    http/             # transport, parsing, normalization
    detection/
      signatures/     # rule engine + signature matching
      positive/       # positive-security model
      anomaly/        # ML/statistical feature extraction + scoring
      bot/            # bot heuristics
      ratelimit/      # rate limiting / DoS controls
    engine/           # additive scoring + decision (mode-aware)
    enforcement/       # action execution, validation chain, ban/allowlist/
                       # virtual-patch stores
    proxy/            # standalone reverse-proxy mode transport/listener
    middleware/        # embedded ASGI middleware mode
    api/               # FastAPI management API (waffy-api process only)
    web/               # control panel
    ipc/               # core<->api Unix socket protocol
    integration/       # SIEM/metrics sinks
    runtime/           # daemon entrypoints for both processes
  config/
    default_config.toml
    rules/             # seed signature set, versioned
    routes/             # example positive-security route configs
  deploy/
    systemd/
    certificates/
  scripts/
    benchmarks/
    attack-lab/         # synthetic corpus + runner, not downloaded at runtime
  tests/
    unit/
    integration/
    security/
  docs/
    MASTER_SPEC.md
    ADDENDUM.md (created when needed)
    ARCHITECTURE.md
    PROGRESS.md
    DEPLOYMENT.md
    PERFORMANCE.md
    API.md
    CODING_STANDARDS.md
    TESTING.md
  prompts/
```

## 24. CONFIGURATION

`config/default_config.toml`, one section per subsystem: `[transport]`,
`[http]` (limits, decompression bounds), `[detection]` (paranoia level,
per-category enable flags), `[anomaly]` (model paths, thresholds, min
sample size), `[ratelimit]`, `[bot]`, `[engine]` (scoring weights,
thresholds, evidence-maturity settings), `[enforcement]` (mode, fail-open/
closed, challenge settings, rate caps), `[allowlist]` (seed entries),
`[api]` (auth, management-source restriction), `[integration]` (SIEM/
metrics endpoints), `[logging]` (redaction field list). No magic numbers
anywhere else in the codebase.

## 25. ERROR HANDLING

A typed exception hierarchy under one `WaffyError` base:
`ConfigurationError`, `TransportError`, `RequestMalformedError`,
`RuleLoadError`, `RuleEngineBudgetExceededError` (non-fatal, logged and
continues), `ModelLoadError`, `ModelInferenceError`, `EnforcementError`,
`ValidationError` (candidate-action validation chain rejections, distinct
per stage), `AuthenticationError`, `IntegrationError`. Each documents when
it's raised and whether the request still proceeds (fail-open per-request)
or the process refuses to start (fail-closed at startup, e.g. malformed
config).

## 26. STARTUP & SHUTDOWN

Startup order: load+validate config → load rule set → load allowlist →
load ban/rule store state → load ML model artifacts if present (missing
artifacts degrade to signature-only scoring, never prevent startup) →
start IPC socket server → start core proxy listener → signal readiness
(`sd_notify`) → begin accepting connections. Graceful shutdown drains
in-flight requests up to a configured timeout, persists any in-memory
ban/rate-limit state that should survive a restart, then exits.

## 27. ACCEPTANCE CRITERIA (high level — each phase prompt has its own
detailed acceptance list)

- A request carrying a clear SQLi/XSS/command-injection payload is
  detected, scored, and — in `ACTIVE` mode — blocked with a generic
  response; the same request in `SHADOW` mode is logged as "would block"
  and forwarded unmodified.
- A benign request against the shipped paranoia-1 rule set is not blocked
  (measured false-positive rate on the benign corpus is reported, not
  assumed zero).
- An allowlisted source is never blocked regardless of score.
- The management API is unreachable without authentication and unreachable
  from outside the configured management source.
- Killing/crashing `waffy-core` results in the configured fail-open/closed
  behavior, verified against a `Fake`, and `waffy-api` stays reachable
  independently (process split holds).
- Full test suite passes, `ruff`/`pyright --strict` clean, on a real POSIX
  run (same discipline pirewall's own history shows is necessary — don't
  trust an all-green run from an environment known to skip
  platform-gated tests without re-verifying on the target platform).

---

This spec is now frozen. Any future changes are additions in
`docs/ADDENDUM.md`, never edits here — identical discipline to pirewall.
