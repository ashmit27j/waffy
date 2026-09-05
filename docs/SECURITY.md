# waffy Security Posture & Threat Model

This document describes waffy's own security posture, its threat model, and
its known limits — what waffy protects against, how it fails, and what is
explicitly out of scope. To report a vulnerability *in* waffy itself, see
the root-level [`SECURITY.md`](../SECURITY.md) instead — this document is
about waffy's design, not about how to disclose a bug in it.

> **Note on this document's history**: it did not exist before this entry
> was written — `README.md` linked to it as if it did, a pre-existing dead
> link discovered and fixed while adding the root-level disclosure-policy
> `SECURITY.md` (see `docs/PROGRESS.md`'s Step C3 entry). Its content below
> is sourced from `CLAUDE.md`'s architecture rules, `docs/MASTER_SPEC.md`,
> and `docs/ARCHITECTURE.md`'s scope-boundary findings — nothing here is a
> new claim invented for this document.

## Threat model

waffy assumes **every byte of every request is attacker-controlled**:
method, path, query string, headers, cookies, body, `Content-Length`,
`Transfer-Encoding` — all of it. This is stated as a non-negotiable rule in
`CLAUDE.md` and enforced structurally: nothing derived from a request may
reach `eval`/`exec`/a shell/`pickle.loads`, and every regex run against
attacker input is bounded (possessive/bounded patterns, a per-request time
budget — see `waffy/detection/signatures/engine.py`).

waffy's layered design exists specifically to contain the blast radius of a
single mistake:

- **Detection → Scoring/Decision → Enforcement are separate layers.** A
  detector (signature match, anomaly score, rate-limit trip) only ever
  produces *evidence* — it cannot itself send a response, close a
  connection, or write a block rule. See `docs/CODING_STANDARDS.md` §1.
- **Exactly one code path may take an enforcement action**
  (`waffy/enforcement/actions.py`) and every candidate action passes a
  fixed, 9-stage validation chain (schema → network validity → allowlist →
  safety → conflict → duplicate → rate-cap → expiration → authorization)
  before it can take effect — see `waffy/enforcement/validation.py`.
- **Fail-safe defaults**: shipped configuration is `SHADOW` mode (observe
  and log, never block) and `fail_open` (if waffy itself crashes or is
  overloaded, traffic passes through to the upstream application rather
  than the site going down). An operator must deliberately opt into
  `ACTIVE` enforcement and/or `fail_closed` after validating against real
  traffic.
- **The static admin allowlist outranks every adaptive/ML-driven decision,
  unconditionally** — no anomaly score or signature match count can
  override it.

## What waffy detects

Signature-based detection (`config/rules/seed_rules.toml`) covers SQL
injection, XSS, command injection, path traversal, LFI/RFI, SSTI, XXE,
insecure deserialization, CRLF injection, open redirect, SSRF, and known
scanner/recon-tool fingerprints — measured true-positive and
false-positive rates for each category are in `docs/PROGRESS.md`'s
attack-lab entries, not asserted here without a number behind them. This is
supplemented by positive-security route constraints (`waffy/detection/positive/`),
rate limiting and bot heuristics (`waffy/detection/ratelimit/`,
`waffy/detection/bot/`), session/CSRF/credential-stuffing checks
(`waffy/detection/session/`), and an evidence-only ML anomaly layer
(`waffy/detection/anomaly/`).

## Known scope boundaries and limits

This list is deliberately specific rather than a generic disclaimer — see
`docs/ARCHITECTURE.md` for the full write-up behind each item:

- **WebSocket traffic is actively denied (not merely uninspected) in all
  three deployment modes.** An application relying on WebSockets will find
  that functionality broken through waffy today — see
  `docs/ARCHITECTURE.md`'s "Known Scope Boundaries" section.
- **GraphQL-specific attacks** (introspection abuse, query complexity/depth,
  batching/aliasing DoS) have no dedicated detection — a GraphQL query is
  only protected to the extent it's scanned as ordinary JSON body text by
  the generic signature engine.
- **HTTP/2 cannot currently be negotiated at all** — uvicorn (this
  project's only ASGI server dependency) has no H2 support and `h2`/
  `hypercorn` are not dependencies, so there is no live HTTP/2 code path,
  malicious or otherwise.
- **Canonical, byte-accurate JA3 fingerprinting is standalone-TLS-mode-only**
  and requires Linux (`socket.MSG_PEEK`); the config toggle
  `tls.ja3_capture_mode` can revert to a lower-fidelity, always-available
  signal. Plaintext and middleware modes never see raw TLS bytes at all.
- **`SqliteRuleStore` persistence is opt-in** — a fresh install is ephemeral
  (ban list, allowlist, and pending-approval queue are lost on restart)
  until an operator configures `enforcement.state_store_path`.
- **Middleware/embedded mode shares a process with the protected
  application** — there is no isolation boundary between waffy's
  in-process state and a compromised application in that mode, unlike the
  two proxy modes. This is a documented trade-off (`waffy/middleware/asgi.py`),
  not a hidden weakness.
- **No production validation against real traffic** — every detection-rate
  and performance number in this repository (`docs/PROGRESS.md`,
  `docs/PERFORMANCE.md`) is measured against a synthetic corpus or an
  in-process fake upstream, not a live deployment. Do not read any
  "100% true-positive" or "0% false-positive" figure as a guarantee against
  real-world traffic shapes it hasn't seen.

## Reporting a vulnerability in waffy

See the root-level [`SECURITY.md`](../SECURITY.md).
