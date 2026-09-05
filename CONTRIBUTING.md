# Contributing to waffy

Thanks for your interest in contributing. This document covers dev
environment setup, how to run the checks locally, and what a pull request
is expected to include. For architecture/coding conventions (module
boundaries, type-safety rules, validation-chain ordering, etc.), see
[`docs/CODING_STANDARDS.md`](docs/CODING_STANDARDS.md) — this file won't
duplicate that content.

## Development environment setup

1. **Prerequisites**: Python 3.12+ and [`uv`](https://docs.astral.sh/uv/).
2. **Windows developers: WSL is required, not optional.** waffy's IPC layer
   (`waffy/ipc/`) uses `asyncio.start_unix_server`, which needs
   `socket.AF_UNIX` — a POSIX-only socket family native Windows Python does
   not implement. Do all development and testing from a WSL Ubuntu shell
   operating on the repo path (e.g. `/mnt/d/...` for a `D:` checkout), not
   a native Windows Python interpreter. See [`README.md`](README.md)'s
   Prerequisites section for the full explanation, including how this
   differs from standalone TLS mode's separate `socket.MSG_PEEK`
   Linux-only assumption.
3. Clone the repo and install dependencies, including the `dev` and `ml`
   optional groups (the ML group is needed to run the anomaly-detection
   test suite):

   ```bash
   uv sync --extra dev --extra ml
   ```

## Running the checks locally

Every one of these must pass before a PR is considered ready — they're the
same commands CI runs (see `.github/workflows/ci.yml`):

```bash
uv run ruff check .
uv run pyright
uv run pytest -q
```

A few notes:

- `pyright` (not `pyright --strict`) is the correct invocation — this
  project's pinned pyright version has no `--strict` CLI flag; strict mode
  is already configured in `pyproject.toml`'s `[tool.pyright]` table.
- The test suite includes property-based (Hypothesis) fuzz tests
  (`tests/unit/test_http_engine.py`) and real-TLS integration tests
  (`tests/integration/`, marked `tls_integration`, requiring the `openssl`
  CLI on `PATH` — they skip, not fail, if it's absent). Neither category
  needs special setup beyond `uv sync --extra dev`.
- To measure test coverage locally: `uv run pytest --cov=waffy --cov-report=term-missing`.
  CI enforces an 80% floor (`[tool.coverage.report].fail_under` in
  `pyproject.toml`) — see `docs/PROGRESS.md` for the currently measured
  percentage. Raise the floor as coverage genuinely improves; never lower
  it to make a regression pass.
- To run the synthetic attack-lab corpus (true-positive/false-positive
  measurement, not part of the pytest suite by default):
  `uv run python scripts/attack-lab/run_corpus.py --report`.

## What a pull request should include

- **Passing checks**: `ruff check .`, `pyright`, and `uv run pytest -q` all
  clean, run locally before pushing (CI will also run them, but don't rely
  on CI to catch something you could catch first).
- **Tests for new behavior**: new detection logic, config fields, or
  request-path code should come with unit (and, where the change touches
  parsing/normalization or another attacker-controlled-input surface,
  property-based) test coverage — see `docs/CODING_STANDARDS.md` and the
  existing test files under `tests/unit/`/`tests/integration/` for the
  established patterns (Protocol + Fake for anything hardware/environment-
  dependent, evidence-only detectors, etc.).
- **`docs/PROGRESS.md` updated** for any change that adds, fixes, or
  changes the status of a tracked deliverable — using the honesty labels
  defined at the top of that file (`Implemented` / `Tested` / `Mocked` /
  `Environment-dependent` / `Not yet validated`). Don't claim something is
  done if it wasn't actually run and verified.
- **`CHANGELOG.md` updated** under an `[Unreleased]` heading for any
  user-facing change (new detection category, new config option, new API
  endpoint, behavior change) — see that file's existing format.
- **No secrets, private keys, certificates, or real attack-corpus payloads**
  beyond synthetic/test data, per `CLAUDE.md`.
- **Architecture constraints preserved**: the one-way module dependency
  flow (`core → config → http → detection → engine → enforcement →
  proxy/middleware/runtime`, with `api`/`web` reachable only via `ipc`),
  the evidence-only boundary for detection/ML code (nothing there may
  itself take an enforcement action), and the fail-safe defaults (`SHADOW`
  mode, `fail_open`) — see `docs/CODING_STANDARDS.md` for the full list.

## Code of conduct

Participation in this project is governed by our
[Code of Conduct](CODE_OF_CONDUCT.md).

## Reporting a security vulnerability

Don't open a public issue for a security vulnerability in waffy itself —
see [`SECURITY.md`](SECURITY.md) for the private reporting process.
