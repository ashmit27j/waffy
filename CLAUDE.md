# CLAUDE.md — waffy project rules (read this every session)

This file is the persistent contract for working on **waffy**. It applies to
every phase, every session, regardless of what the phase prompt asks for. If
anything here conflicts with a phase prompt, this file wins.

## What this project is

A per-host, application-layer Web Application Firewall (WAF), deployable
standalone on any individual machine in front of (or embedded into) a web
application or API. Where pirewall watches *network flows* and cannot see
inside encrypted or application-layer payloads, waffy sits *inline with
decrypted HTTP traffic on the host itself* and inspects real request/response
content: URLs, headers, cookies, query strings, request bodies (JSON, form,
multipart, XML), and response bodies where relevant. Full spec is in
`docs/MASTER_SPEC.md` — read the relevant numbered sections before touching a
subsystem (the phase prompt tells you which sections apply). `docs/MASTER_SPEC.md`
is frozen once written and stays verbatim; later clarifications go in
`docs/ADDENDUM.md` files, same pattern pirewall used — never edit the frozen
spec in place.

Current status of every phase is tracked in `docs/PROGRESS.md`. Create it in
Phase 1 and update it at the end of every phase, in the same style pirewall
used: what's Implemented / Tested / Mocked / Environment-dependent / Not yet
validated, with honest per-item labels, never a blanket "done."

## Session start checklist

At the start of every session, before writing code:

1. Read `docs/PROGRESS.md` to see what's already done and what phase you're on.
2. Read the phase prompt you were given (`prompts/phase-XX-*.md`).
3. Read the `docs/MASTER_SPEC.md` sections that prompt references.
4. Read any `docs/ADDENDUM*.md` files that exist — newer addenda win over
   older ones and over the frozen spec, same rule pirewall used.
5. If code already exists for this area, inspect it first — preserve correct
   existing work, don't blindly rewrite.

## Non-negotiable architecture rules

- **This process sits directly in the request path of real, potentially
  hostile, untrusted traffic. Every byte of every request is attacker-
  controlled input**, including headers, cookies, URL, method, body, and
  even things like content-length and transfer-encoding. Nothing derived
  from a request may ever reach `eval`, `exec`, a shell, a format string
  used to build a shell/SQL/log-injection-prone string, `pickle.loads` on
  untrusted bytes, or an unbounded regex/backtracking construct without an
  explicit timeout/step budget. This rule has no exceptions and no "trusted
  caller" shortcut anywhere in the codebase.
- **Detection → Scoring/Decision → Enforcement are separate layers**, never
  collapsed into one function/module. A detector reports *evidence*
  (a matched signature, an anomaly score, a rate-limit trip) — it never
  itself sends a response, closes a connection, or writes a block rule.
- **ML/statistical anomaly scoring produces evidence, never commands.** The
  anomaly/ML layer feeds a `RequestAssessment`/`ThreatAssessment`-style
  evidence object. Nothing in that layer may construct an enforcement
  action, send an HTTP response, or mutate any block/allow list.
- **Every candidate enforcement action (new IP ban, new virtual-patch rule,
  new rate-limit entry) passes a full validation chain in a fixed order**:
  schema → network/target validity → allowlist → safety → conflict →
  duplicate → rate-cap → expiration → authorization. No shortcuts, no
  "trusted" callers that skip validation. Mirror pirewall's proven ordering;
  don't invent a different order per subsystem.
- **Safety validation is mandatory and specific**: an enforcement action must
  never be able to lock out waffy's own management interface, the
  configured admin/management source, or (in reverse-proxy mode) the entire
  upstream application for all clients — and must never be broader than the
  evidence that generated it (e.g. a signature match on one parameter must
  not produce a rule blocking the whole IP's access to unrelated routes
  unless the decision layer explicitly escalated to that scope).
- **Exactly one authorized code path may take an enforcement action**
  (return a block/challenge response, write to the ban list, deploy a
  virtual-patch rule). Nothing else short-circuits to enforcement.
- **Hardware/environment-dependent components get a Protocol/interface plus a
  Fake test implementation.** At minimum: the upstream HTTP client
  (`UpstreamClient` Protocol, real `httpx`-based implementation, `Fake` for
  tests), the persistent ban/rule store (`RuleStore` Protocol, real
  file/sqlite-backed implementation, in-memory `Fake`), the TLS certificate
  provider (`CertificateProvider` Protocol, real ACME/file-based
  implementation, `Fake`), and the challenge/CAPTCHA verifier (`ChallengeVerifier`
  Protocol, real implementation, `Fake`). All core logic — parsing, rule
  matching, scoring, decisioning — must be testable without a real network
  socket, a real upstream server, or a real TLS certificate.
- **One canonical feature-extraction module for the ML/anomaly layer.**
  Training-time and runtime inference call the *same* extractor function —
  never reimplement request-feature math twice.
- **Never auto-modify host network configuration, DNS, or another
  application's files.** TLS material and deployment templates are
  generated/documented, not silently applied to a live system without an
  explicit deploy step the operator runs themselves.
- **Default enforcement mode is `SHADOW` (observe/log only, never block or
  challenge real traffic) and default failure mode is `fail_open`** —
  meaning if waffy itself crashes or is overloaded, traffic passes through
  to the upstream application unfiltered rather than the site going down.
  This mirrors pirewall's A1/A6 addenda exactly and for the same reason:
  a first deployment against real traffic has real false-positive risk, and
  breaking someone's production site is worse than temporarily not
  filtering it. Don't quietly change these defaults in config templates.
- **The static admin-defined allowlist outranks every adaptive/ML-driven
  decision, unconditionally.** No anomaly score, no signature match count,
  no enforcement mode overrides it.
- **The management API / control-panel process never imports or calls the
  request-path proxy/enforcement engine directly.** It only talks to the
  core enforcement process over a defined local IPC channel (Unix domain
  socket). This must be true at the import-graph level.
- **waffy is IPv4-and-IPv6 capable at the HTTP layer** (unlike pirewall's
  deliberate v1 IPv4-only network-layer scope) since it operates above the
  network layer entirely — but document explicitly in `docs/ARCHITECTURE.md`
  which of IPv4/IPv6 client-address features (rate limiting, ban lists,
  reputation lookups) are implemented for both families vs. IPv4-only if you
  have to cut scope; don't silently under-support IPv6 clients.
- **No dependency on pirewall, ever, at the code level.** waffy may *emit*
  events in a format a SIEM (Wazuh) or a human could correlate with
  pirewall's own events (shared `SecurityEvent`-shaped JSON, shared
  timestamp/source-IP conventions) — that's the full extent of the
  relationship. Never import pirewall, never call a pirewall socket/API,
  never assume pirewall is installed on the same host.

## Type safety rules

- Python 3.12+, full annotations on every function signature and class
  attribute.
- Pydantic v2 models for everything that crosses a boundary: config, API
  request/response, IPC messages, and every domain object listed in
  `docs/MASTER_SPEC.md` §9. No raw untyped dicts flowing through core code.
- `Any` requires an inline comment explaining why it's unavoidable (raw
  request bytes before parsing are a legitimate `bytes`/`bytearray`, not
  `Any` — don't reach for `Any` as a way to skip validating attacker input).
- Enums/`Literal` for anything with a finite set of values (actions, threat
  levels, rule status, event types, HTTP methods you explicitly support,
  enforcement modes).
- Type checker: **pyright in strict mode** (`pyright --strict`), configured
  in `pyproject.toml`. Run it before considering any phase done.

## Coding hygiene

- No file should try to do more than one subsystem's job. If a file is
  getting large, split it along the module boundaries in
  `docs/MASTER_SPEC.md` §35 (repository structure).
- No magic numbers for thresholds — they live in `config/default_config.toml`
  and are loaded through the config models.
- No circular imports between `core` → `http` (parsing/normalization) →
  `detection` (signatures/anomaly) → `engine` (scoring/decision) →
  `enforcement` (actions/responses) → `api`/`web`. Dependencies flow one
  direction; `core.models` has no dependents that flow backward.
- Every regex used against attacker-controlled input has a documented
  worst-case complexity consideration (avoid catastrophic backtracking —
  prefer possessive/atomic patterns, bounded quantifiers, or a
  non-backtracking engine) and a per-request time/step budget enforced by
  the rule engine, not by hoping the pattern is safe.

## Dependencies

Default to: Python 3.12+, `uv`, Pydantic v2, FastAPI + Starlette/uvicorn
(or an equivalent ASGI stack — pick one and stay consistent), `httpx` for the
upstream client, Pytest, Ruff, pyright, and stdlib. A rule/pattern-matching
library (e.g. `regex` for possessive quantifiers, or a hyperscan binding) and
a lightweight ML library (scikit-learn, matching pirewall's stack) may be
added when the relevant phase needs them — name it explicitly in that
phase's `docs/PROGRESS.md` entry and in `docs/ARCHITECTURE.md`. Anything
else — a database, a message broker, a full frontend framework, a
third-party WAF/CRS engine dependency — ask first and say why in
`docs/ARCHITECTURE.md`.

## Labeling honesty

Never claim something works if it hasn't been run and verified. Every
non-trivial deliverable gets one of these labels in your summary and in
`docs/PROGRESS.md`:

- **Implemented** — code exists and matches the spec.
- **Tested** — implemented + covered by a passing automated test.
- **Mocked** — behind a Fake implementation for testability; the real
  backend (real socket, real upstream server, real TLS cert, real
  CAPTCHA provider) has not been exercised.
- **Environment-dependent** — cannot be verified outside a real deployment
  (real traffic, a real reverse-proxy target, a real cert authority);
  describe exactly what a human needs to do to verify it.
- **Not yet validated** — written but not run/tested this session.

Never fabricate metrics, never claim a rule was deployed/enforced if it
wasn't, never report fake detection-rate numbers, and never claim "blocks
OWASP Top 10" or similar marketing language without a specific, tested
attack corpus backing the claim (see the attack-lab phase).

## Definition of done for a phase

A phase is not done until:

1. `ruff check .` is clean.
2. `pyright --strict` is clean (or has zero *new* errors if the phase
   explicitly says pre-existing errors are out of scope).
3. `pytest` passes, including new tests for everything in that phase's scope.
4. `docs/PROGRESS.md` is updated: phase marked complete, each acceptance
   item labeled per the honesty rules above, any deviations from the phase
   prompt explained.
5. Any new public module/class/function has a docstring explaining its
   contract.
6. You have **not** implemented anything from a later phase's scope —
   implementation order matters, especially: request parsing/normalization
   before detection, detection before scoring/decision, decision before
   enforcement, enforcement before the API that manages it.

## Do not

- Do not implement enforcement (blocking/challenging real traffic) before
  detection, scoring, decision, and the full validation chain all exist and
  are tested.
- Do not implement ML/anomaly-based blocking before the feature schema is
  frozen and versioned, and before it has run in an observe-only capacity.
- Do not fabricate metrics, mock the upstream connection and report it as a
  real end-to-end test, or silently skip the honesty labels.
- Do not modify host TLS material, systemd state, or another application's
  files during a session unless the phase prompt explicitly says this is a
  real-deployment step and you've confirmed that with the user first.
- Do not commit secrets, private keys, certificates, session tokens, or real
  attack-corpus files containing anything beyond synthetic/test payloads.
- Do not add a dependency, database, message broker, or full frontend
  framework not listed above without asking.
- Do not import, call, or otherwise depend on pirewall from any waffy code.
