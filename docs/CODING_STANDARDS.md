# waffy Coding Standards & Architecture Conventions

This document captures coding standards, type safety rules, and conventions for developing **waffy**.

## 1. Core Principles (from CLAUDE.md)

1. **Hostile Input Boundary**: Every byte in a request is untrusted. No dynamic string execution (`eval`, `exec`, shell calls, `pickle.loads` on untrusted input).
2. **Layer Separation**:
   - `http/`: Transport, parsing, and normalization.
   - `detection/`: Signature matching, positive security, bot checks, ML scoring. Emits *evidence only*.
   - `engine/`: Additive scoring and decision matrix. Computes threat level and proposed action.
   - `enforcement/`: Executes actions, applies validation chain to persistent rules, manages ban list/allowlist.
   - `api/` & `web/`: Management interface. Talks *only* via IPC to `waffy-core`.
3. **Validation Chain Ordering**:
   `schema -> network/target validity -> allowlist -> safety -> conflict -> duplicate -> rate-cap -> expiration -> authorization`
4. **Protocols & Fakes**:
   All hardware/environment-dependent components (`UpstreamClient`, `RuleStore`, `CertificateProvider`, `ChallengeVerifier`, `EventSink`) define a `typing.Protocol` and provide a standalone `Fake` implementation for tests.
5. **Fail-Safe Defaults**:
   - Default `enforcement.mode` = `"shadow"` (log-only, never block).
   - Default `failure.mode` = `"fail_open"` (allow traffic if WAF errors).

## 2. Python & Type Checking Standards

- Python 3.12+ features (modern union syntax `X | Y`, `StrEnum`, `tomllib`).
- Full type annotations on all functions and methods.
- Type checker: `pyright --strict` with zero errors.
- Linters: `ruff check .` with configured rules.
- Pydantic v2 domain models for all boundary objects (`core/models/domain.py`).

## 3. Privacy & Redaction

- Sensitive fields in query parameters, headers, bodies, and logs are redacted according to `logging.redact_fields`:
  - `password`, `token`, `secret`, `authorization`, `cookie`, `set-cookie`, `api_key`, `access_token`, etc.
- Matched signature snippets in logs must mask the exact sensitive credential while preserving match context.

## 4. Module & Dependency Hierarchy

Dependencies flow one way:
```
core -> config -> http -> detection -> engine -> enforcement -> (proxy | middleware | runtime)
                                                                 ^
                                              api / web -> ipc -/
```
No circular imports. `waffy-api` must never directly import proxy or enforcement request-path runtime modules.
