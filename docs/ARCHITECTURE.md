# waffy Architecture Notes

This document records architecture-level decisions that don't belong in the
frozen `docs/MASTER_SPEC.md` (per the frozen-spec convention, clarifications
and decisions made after the spec was written go here or in
`docs/ADDENDUM.md` files, never edited into the spec itself) and dependency
additions with their justification, per `CLAUDE.md`'s "ask first and say why"
rule for anything beyond the named default stack.

This file is new as of the Phase 9 hardening tasks (`prompts/01`-`07`) and
will grow as later tasks add entries — it did not exist before prompts/04.

---

## Persistence audit (prompts/05) — does enforcement state survive a restart?

**Audit method**: grepped the codebase for every implementation of
`waffy.core.interfaces.RuleStore` (the Protocol covering bans, allowlist
entries, and virtual patches), and traced how `approve_pending`/`reject_pending`
(the "pending-approval queue") are actually stored.

**Finding, before this task**: `RuleStore` had exactly **one** implementation
anywhere in the codebase: `tests/helpers/fakes.py::FakeRuleStore`, three
plain in-memory `dict`s, explicitly a test double. No file/sqlite-backed
implementation existed despite `CLAUDE.md` naming one as a required
component ("the persistent ban/rule store (`RuleStore` Protocol, real
file/sqlite-backed implementation, in-memory `Fake`)"). There is also no
separate "pending queue" store — `approve_pending`/`reject_pending`
(`waffy/ipc/server.py`) operate on the same `RuleStore.add_ban`/`list_active_bans`/
`remove_ban` methods as regular bans, distinguished only by `BanEntry.status`.
`waffy/enforcement/validation.py`'s "persistent action validation chain"
naming refers to the *duration* of an enforcement action (a ban that outlives
a single request, as opposed to a per-request decision) — it does not itself
read or write disk; it only builds a `BanEntry` and returns it, and the
*caller* is responsible for calling `rule_store.add_ban()`.

**Conclusion**: **before this task, 100% of waffy's active security state —
ban list, dynamic allowlist entries, and pending-approval bans — was
in-memory only and was silently lost on every restart or crash**, with no
operator-visible warning anywhere in the codebase.

**What changed**: `waffy/enforcement/store.py` adds:
- `InMemoryRuleStore` — the same ephemeral behavior as before, but now a
  named, documented, *production* class (not a test-only Fake), used as the
  explicit default.
- `SqliteRuleStore` — a real, disk-backed implementation (stdlib `sqlite3`,
  no new dependency, no database server), selected by setting the new
  `EnforcementConfig.state_store_path` config field. Every synchronous
  sqlite3 call is offloaded via `asyncio.to_thread`. Proven to survive a
  simulated restart (`tests/unit/test_enforcement_persistence.py::test_sqlite_rule_store_survives_simulated_restart`
  constructs a second, independent `SqliteRuleStore` instance against the
  same file and confirms it sees the first instance's writes) and proven to
  be a true drop-in replacement — `AllowlistManager` and the 9-stage
  `ActionValidationChain` needed zero code changes to work against it
  (`test_allowlist_manager_and_validation_chain_work_unmodified_with_sqlite_store`).
- `build_rule_store(config)` — picks the backend, and logs an explicit
  `logging.WARNING` (`waffy.enforcement.store` logger) whenever the ephemeral
  `InMemoryRuleStore` is chosen, so "in-memory, state lost on restart" can
  never happen silently going forward, whether or not an operator has
  configured persistence.

**Current state, honestly**: persistence is real and tested, but **opt-in**
— `state_store_path` defaults to unset, so a fresh install is still
ephemeral by default until an operator configures it (see
`docs/DEPLOYMENT.md`). This was a deliberate choice: this task's scope was
"does state survive a restart, and can it," not "change the zero-config
default behavior of every existing deployment/test that constructs a
`RuleStore` today" — flipping the *default* to always-persistent would be a
larger behavioral change than this task asked for, and risks masking a
misconfigured/unwritable `state_store_path` behind a silent fallback. The
validation chain order (9 stages, `waffy/enforcement/validation.py`) is
completely unchanged — this was a storage-backend swap only.

---

## Dependency decisions

### Step B2 — `hypothesis` added as a dev-only dependency

**Decision**: `hypothesis>=6.100.0` added to `pyproject.toml`'s
`[project.optional-dependencies].dev` group only — it is **not** a runtime
dependency and never ships with the deployed `waffy-core`/`waffy-api`
processes. It's used exclusively by `tests/unit/test_http_engine.py`'s
property-based fuzz tests.

**Why**: `waffy/http/parser.py`, `waffy/http/normalize.py`, and
`waffy/http/body.py` all handle 100% attacker-controlled input per
`CLAUDE.md`, but before this step only had table-driven tests against known
evasion techniques — no generative coverage searching for edge cases the
table didn't anticipate. Hypothesis is the standard Python property-based
testing library for exactly this job (input-space search plus automatic
shrinking to a minimal failing example) and is widely used in security-
sensitive Python parsers for this reason.

**Justification for the dependency addition itself**: dev/test-only tooling
carries far less risk than a runtime dependency (per `CLAUDE.md`'s "ask
first" rule, which is squarely aimed at things that ship in the request
path) — it never touches a deployed process or the request path, and adding
it follows the same precedent as `pytest`/`pytest-asyncio`/`ruff`/`pyright`
already being dev-only entries in the same `[project.optional-dependencies].dev`
group.

**What it found**: a real bug, on the first property-based run against
`parse_multipart_metadata()` — see "Bug found by Hypothesis in Step B2"
below.

### Bug found by Hypothesis in Step B2 — `parse_multipart_metadata` raised an unhandled `ValueError`

**Finding**: `waffy/http/body.py::parse_multipart_metadata()` raised a raw
stdlib `ValueError` ("Header values may not contain linefeed or carriage
return characters") for any `content_type_header` containing a bare CR or
LF character — e.g. Hypothesis's minimal failing example was
`content_type='\r0'`. Every sibling function in the same file
(`decompress_body`, `parse_safe_xml`) follows the "return safely or raise
the one documented `RequestMalformedError`" contract; this function was the
one exception (literally).

**Root cause**: the function constructed an `email.message.EmailMessage()`
purely to do `msg["Content-Type"] = content_type_header` — Python's
`email.policy` header-store validation rejects embedded CR/LF and raises
`ValueError`. Reading the rest of the function showed `msg` was **never
referenced again after that assignment** — the actual boundary-marker
extraction below it parses `content_type_header.split(";")` independently.
The `EmailMessage` construction was dead code, and it was also the only
source of a non-`RequestMalformedError` exception in the function.

**Fix**: deleted the unused `EmailMessage` construction entirely (3 lines,
`waffy/http/body.py`) rather than wrapping dead code in a defensive
try/except. This is a strict simplification — no behavior the function
actually used was removed, and the CR/LF-input case that used to crash now
returns cleanly (or falls into the existing `{"raw_parts": len(body)}`
no-boundary-found path, exactly like any other content-type with no
`boundary=` parameter).

**Practical exposure before the fix**: `parse_multipart_metadata` is
exported as public API (`waffy.http.__all__`) but in production is only
ever called from inside `parse_body()`'s own `try/except Exception` block,
which would have caught and correctly re-raised this as
`RequestMalformedError` anyway — so the fix closes a genuine contract
violation in a public function (and a real crash for anyone calling it
directly, e.g. a future caller or a test), not a live unhandled-exception
path through the normal request pipeline. Confirmed by re-running the
original 5,000-example failing case (now passes) plus a new fuzz test
(`test_property_parse_multipart_metadata_never_raises_unexpected_exception`)
and a direct regression test
(`test_hypothesis_found_bug_multipart_content_type_with_crlf_no_longer_crashes`),
both in `tests/unit/test_http_engine.py`.

### prompts/04 — JA3/JA4 TLS fingerprint extraction: no new dependency added

**Decision**: real TLS ClientHello fingerprinting (`waffy/proxy/tls_fingerprint.py`)
was implemented using **only the Python standard library** (`ssl`, `hashlib`,
`struct`) plus the project's existing `uvicorn` dependency — no new
dependency was added to `pyproject.toml`.

**Why this was possible without a new dependency**: canonical JA3 needs the
*raw, pre-handshake* ClientHello bytes (offered cipher list, extension IDs in
offered order, supported groups, EC point formats). Those bytes are a
small, fixed-format TLV structure (RFC 8446 §4.1.2) that can be parsed
directly with `struct`/bounds-checked slicing — no TLS library is actually
needed to *parse* a ClientHello once you have the bytes. `waffy/proxy/tls_fingerprint.py::parse_client_hello`
+ `compute_ja3` implement this directly, GREASE-filtered per RFC 8701, and
are unit-tested in `tests/unit/test_session_bot_ratelimit.py` against a
**real** ClientHello captured from a real local Python TLS client (not a
hand-typed byte fixture).

**Why this is NOT the production path today, and what would need a
dependency (or a larger change) to fix that**: getting those raw
pre-handshake bytes out of a *live* connection requires seeing them before
Python's `ssl` module consumes them into a handshake. Python's public `ssl`
API (and uvicorn's use of it) does not expose raw ClientHello bytes at any
hook point — `SSLContext.set_servername_callback` gives you SNI only, not
the byte buffer. The only ways to get real byte-level access are:

1. **A parallel, hand-rolled TLS listener** using `ssl.SSLContext.wrap_bio()`
   with a `MemoryBIO` you feed yourself, so you own the raw bytes before
   they're consumed. This is a materially larger undertaking than this
   task's scope (it re-implements the accept-and-handshake path uvicorn
   already provides) and was deliberately **not** done here — flagged below
   as a follow-up, not attempted, to avoid introducing a second, less-tested
   HTTP/TLS transport implementation into a security-sensitive request path
   (directly against `CLAUDE.md`'s parsing-safety rules).
2. **A packet-capture-oriented library** (`scapy`, `pyshark`) — wrong model
   for waffy, which terminates TLS itself rather than sniffing someone
   else's traffic; would add a heavy, unjustified dependency for no benefit
   over (1).
3. **A lower-level TLS binding** (e.g. exposing OpenSSL's `SSL_get_client_hello_*`
   family directly) — no well-established, actively-maintained pure-Python
   package does this safely today; hand-rolling FFI bindings against
   OpenSSL internals is a bigger, riskier undertaking than either of the above.

**What's actually wired into production today**
(`waffy/proxy/standalone.py` + `waffy/proxy/tls_fingerprint.py`):
`compute_fingerprint_from_ssl_object()` derives a **real, but not
byte-identical-to-canonical-JA3** fingerprint from the *post-handshake*
`ssl.SSLObject`/`SSLSocket` available via `transport.get_extra_info("ssl_object")`
— specifically the negotiated TLS version, negotiated cipher, the client's
offered-and-server-supported cipher intersection (`SSLSocket.shared_ciphers()`,
a genuine signal sourced from the real ClientHello via OpenSSL's
`SSL_get_shared_ciphers`, not fabricated), and the negotiated ALPN protocol.
It is labeled distinctly (`waffy-tlsfp-v1:` prefix) in every fingerprint
value, log line, and config field so it is never mistaken for a canonical
JA3/JA4 hash by an operator populating
`config.bot_detection.known_bad_tls_fingerprints`.

Capture is wired into `waffy/proxy/standalone.py::build_standalone_uvicorn_config`
via `build_ja3_capturing_protocol`, which subclasses uvicorn's internal
`H11Protocol` to record a per-connection fingerprint into a bounded
`TlsFingerprintRegistry` (keyed by `(peer_ip, peer_port)`) on `connection_made`,
and forgets it on `connection_lost`. `waffy/http/pipeline.py`'s
`WaffyPipelineApplication` accepts an optional
`tls_fingerprint_lookup: Callable[[str, int], str | None]` — a plain callable,
not an import of the proxy layer, preserving the one-way
`core -> config -> http -> detection -> engine -> enforcement -> proxy`
module dependency flow from `CLAUDE.md` — and passes its result into
`BotDetectionEngine.assess()`. If no lookup is wired (plaintext mode,
middleware mode, or a uvicorn version whose internal `H11Protocol` can't be
subclassed), the fingerprint is `None` and stays a neutral, zero-weight
signal — never a crash, matching `waffy/proxy/plaintext.py`'s documented
"absent TLS signal" contract for the no-JA3 case.

**Follow-up (not done in prompts/04) — investigated in prompts/13, confirmed
architecturally impractical without disproportionate complexity and real
handshake-correctness risk; NOT implemented.** `parse_client_hello`/
`compute_ja3` are already written and tested against real captured bytes and
remain ready to be wired to a capture path the moment one exists safely — no
rework needed on the algorithm side — but no such path was built. Full
investigation, so a future attempt doesn't have to re-derive this from
scratch:

The fundamental obstacle is that `waffy/proxy/standalone.py` hands its
`ssl.SSLContext` to uvicorn via `ssl_context_factory`, which uvicorn passes
straight through to `loop.create_server(..., ssl=ssl_context)`. Under the
hood this makes `asyncio`'s selector event loop perform the TLS handshake
*inside the transport layer*, consuming and decrypting the raw ClientHello
bytes via OpenSSL before any of waffy's own code (or even uvicorn's
`H11Protocol.connection_made`) runs. By the time our code can react to a
connection at all, the raw pre-handshake bytes are already gone with no
public API to recover them — this is the root cause of the whole
"not byte-identical" caveat, not a bug in `build_ja3_capturing_protocol`.

Two candidate ways around this were evaluated, both rejected:

1. **A parallel raw-socket accept loop using `socket.MSG_PEEK`.** Bypass
   `loop.create_server(ssl=...)` (and therefore uvicorn's own listener)
   entirely: accept the raw TCP connection ourselves, use
   `loop.add_reader(fd, ...)` plus a manual, low-level
   `sock.recv(n, socket.MSG_PEEK)` to inspect the ClientHello *without*
   removing it from the kernel's socket receive buffer, parse it with the
   already-tested `parse_client_hello`, and only then hand the connection to
   `loop.start_tls()` to perform the real handshake against the
   still-unconsumed bytes. This is the technically-correct version of the
   nginx `ssl_preread` / HAProxy `req.ssl_hello_type` pattern. The blocker:
   `asyncio.Protocol`/`Transport`'s normal read path (which any use of
   `loop.create_server()` or `asyncio.start_server()` triggers, even without
   `ssl=`) *removes* bytes from the kernel buffer into its own internal
   buffer the moment they're read — true `MSG_PEEK` semantics require
   operating on the bare `socket.socket` object before any asyncio
   Transport/Protocol machinery has touched it. Doing this correctly means
   reimplementing the entire connection-acceptance and TLS-upgrade sequence
   uvicorn's `Server.startup()` currently provides — not a small addition,
   a parallel, independently-correct implementation of a security-critical
   path (exactly what `CLAUDE.md`'s parsing-safety rules and this task's own
   "don't guess at an approach that silently breaks the TLS handshake"
   constraint warn against).
2. **`asyncio.BaseEventLoop.start_tls()`'s `StreamReader`-buffer transfer.**
   Inspecting CPython 3.14.4's actual `start_tls()` source (this project's
   test/dev environment) turned up a real mechanism: if the plaintext
   protocol being upgraded is an `asyncio.StreamReaderProtocol` (i.e. built
   via `asyncio.start_server()`'s `(reader, writer)` stream API), any bytes
   already delivered into the `StreamReader`'s internal buffer but not yet
   consumed by an application `read()` call are automatically moved into the
   new TLS layer's incoming buffer before the handshake starts — a fix
   tracked upstream as `gh-142352`. In principle this would let us: accept
   via `asyncio.start_server()`, poll the reader's buffered (not yet
   `read()`-consumed) bytes until we have a full ClientHello, parse it, then
   call `start_tls()` and have the *same* bytes safely carried over into the
   real handshake — no custom accept loop needed. **Rejected anyway**: this
   depends on (a) a very recently landed, high-numbered CPython issue fix
   that is not part of `asyncio`'s long-standing, version-independent public
   contract, with no confirmation it exists on Python 3.12 or 3.13 — the
   minimum version `CLAUDE.md` requires this project to support — and
   (b) reading `StreamReader`'s private `_buffer` attribute directly (no
   public "peek without consuming" API exists on `StreamReader`). Building a
   security-critical TLS-handshake behavior on an undocumented, recent-only
   CPython internal is precisely the "guess at an approach that silently
   breaks the TLS handshake" failure mode this task was explicitly told to
   avoid — on Python 3.12/3.13 (in scope for this project), the bytes would
   most likely be dropped rather than transferred, breaking every single TLS
   connection to standalone mode silently.

**Conclusion (prompts/13, historical)**: both concrete paths to byte-perfect
canonical JA3 in standalone TLS mode require either reimplementing uvicorn's
connection-acceptance/TLS-upgrade internals from scratch, or relying on
undocumented, version-fragile CPython internals in a security-critical code
path. Per that task's explicit "stop and report rather than force a fragile
fix" instruction, no implementation was attempted at the time. **This
conclusion was later revisited and option 1 was in fact built — see the
prompts/13b entry immediately below.**

### prompts/13b — Byte-Accurate Canonical JA3, Implemented (supersedes the prompts/13 blocker above)

**Outcome: option 1 above (a parallel raw-socket accept loop using
`socket.MSG_PEEK`) was implemented as `waffy.proxy.standalone.PreAcceptTlsServer`,
tested against real TLS handshakes including GREASE-bearing ClientHellos, and
is production-usable behind an explicit config toggle.** The prompts/13
investigation's technical analysis of *why* this is hard (reproduced above)
remains accurate — this was a genuine, carefully-tested custom-accept-loop
project, not an incremental patch, exactly as that investigation recommended
any future attempt should be scoped.

**What changed, concretely**:

- `PreAcceptTlsServer` owns its own TCP accept loop (`loop.sock_accept()` on
  a socket bound via `uvicorn.Config.bind_socket()`, so port-binding/backlog
  semantics stay identical to uvicorn's own listener) instead of delegating
  to `loop.create_server(ssl=...)`. This sidesteps the exact obstacle
  prompts/13 identified: nothing asyncio-managed touches the socket before
  the peek happens, so `socket.MSG_PEEK` semantics are genuine, not
  approximated.
- `peek_client_hello_bytes()` peeks the bare `socket.socket` directly
  (non-blocking `sock.recv(n, socket.MSG_PEEK)` plus `loop.add_reader()` to
  wait for more without blocking the event loop), bounded on both size
  (`MAX_CLIENT_HELLO_BYTES` — the same 16640-byte cap `parse_client_hello`
  already enforced) and wall-clock time (`peek_timeout_seconds`, default
  2.0s) — never an unbounded read against attacker-controlled input, per
  `CLAUDE.md`. A malformed/truncated declared record length is handled the
  same way `parse_client_hello` already handled it: capped, never looped.
- Once the ClientHello bytes are peeked (not consumed), the *same untouched
  socket* is handed to `loop.create_connection(_NullPlainProtocol, sock=...)`
  and then `asyncio.loop.start_tls()` — the public, documented API — to
  perform the real handshake. `parse_client_hello`/`compute_ja3` (unchanged
  since prompts/04) then compute the byte-accurate canonical JA3 from the
  peeked bytes, including RFC 8701 GREASE stripping — verified with a real
  captured Chrome-shaped ClientHello in `test_ja3_filters_grease_values`
  (prompts/04, still passing) and end-to-end against a real client
  connection in `test_preaccept_peek_produces_correct_canonical_ja3`
  (prompts/13b).
- **Fails closed on the fingerprint only, never the connection**: if the peek
  times out, the client sends non-TLS traffic, or parsing fails for any
  reason, `PreAcceptTlsServer` falls through to
  `build_fingerprint_aware_protocol()`'s existing post-handshake
  `SSLObject`-derived signal (prompts/04's fallback) for that one connection
  — the handshake and request are never dropped because of a peek failure.
  Proven by `test_graceful_fallback_non_tls_traffic_and_peek_timeout`: a
  connection that sends garbage or nothing at all is closed cleanly, bounded
  by `peek_timeout_seconds` + `handshake_timeout_seconds`, and the listener
  keeps serving normal clients afterward without restart.
- **Operator revert switch**: `waffy.config.models.TlsConfig.ja3_capture_mode`
  (`"clienthello_peek"` default / `"post_handshake"` / `"disabled"`) lets an
  operator disable the new pre-accept stage without a code change if it
  misbehaves in production — `"post_handshake"` skips the peek entirely and
  always uses the pre-13b `SSLObject`-derived signal;
  `"disabled"` captures nothing at all, matching plaintext mode's neutral
  no-JA3 contract. Covered by
  `test_capture_mode_post_handshake_skips_peek_uses_ssl_object_signal` and
  `test_capture_mode_disabled_never_populates_registry`.
- **TLS version floor unchanged**: `PreAcceptTlsServer` is handed the exact
  `ssl.SSLContext` `build_ssl_context()` already produces (still `TLSv1_2`
  minimum) — the new accept loop only decides *when* the handshake starts
  (after a peek instead of immediately), never *how* (cipher/version
  policy).
- **Linux-only assumption, correctly scoped**: `socket.MSG_PEEK` is POSIX;
  this is only exercised on the project's WSL/Linux dev and CI environment.
  This is a *separate* Linux dependency from the one `CLAUDE.md` already
  documents for the IPC layer (`socket.AF_UNIX`/`asyncio.start_unix_server`)
  — both point at the same practical constraint (deploy on Linux) but for
  different subsystems; conflating them would understate how POSIX-coupled
  this project already is. Not verified on native Windows sockets — the
  Windows/WSL development note (`README.md`, `docs/DEPLOYMENT.md`) covers
  development only, not a claim that either subsystem runs on native
  Windows in production.
- **Scope not covered**: `PreAcceptTlsServer` is a standalone, directly
  testable/usable class — it is not yet wired into
  `waffy/runtime/core_daemon.py`'s startup sequence, matching the
  pre-existing, already-documented gap (prompts/07's Task 07 entry in
  `docs/PROGRESS.md`) that `core_daemon.py`/`waffy/runtime/__main__.py` does
  not yet construct or bind a real standalone-mode listener at all — that
  wiring is future work independent of this task, not a regression
  introduced here.

**Tests** (`tests/integration/test_task13b_preaccept_ja3.py`, all real TLS,
skip — not fail — if `openssl` isn't on `PATH`, matching prompts/03's
convention): byte-accurate canonical JA3 matches an independently-computed
reference for the exact same client config
(`test_preaccept_peek_produces_correct_canonical_ja3`); a real end-to-end
HTTPS request through `WaffyPipelineApplication` to a fake upstream still
completes normally, proving no bytes are lost
(`test_real_handshake_completes_through_preaccept_stage`); both non-TLS
traffic and a silent connection degrade gracefully and boundedly
(`test_graceful_fallback_non_tls_traffic_and_peek_timeout`); both
`ja3_capture_mode` revert paths behave as documented (the two tests named
above). `docs/PROGRESS.md`'s Task 13 entry is preserved as-is (that
investigation happened and was accurate) with a pointer added to this
prompts/13b entry rather than being rewritten.

**Known-bad fingerprint list**: `config.bot_detection.known_bad_tls_fingerprints`
(`waffy/config/models.py::BotDetectionConfig`) is an empty-by-default,
operator-managed local list — not a live threat-intel feed. Values can be
either byte-accurate canonical JA3 hashes (32-char hex, when
`tls.ja3_capture_mode = "clienthello_peek"`, the default — see prompts/13b
above) or `waffy-tlsfp-v1:`-prefixed values (when `ja3_capture_mode` is
`"post_handshake"` or a same-connection peek fallback occurred). An operator
populating this list should know which mode their deployment runs in, since
the two value shapes are not interchangeable.

**FIXED in prompts/11** (see `docs/PROGRESS.md`'s dedicated Task 11 entry for
the commit): `config/default_config.toml`'s `[bot]` TOML section didn't
actually populate `WaffyConfig.bot_detection` — `WaffyConfig.model_validate()`
expects a `[bot_detection]` section name to match the Pydantic field name,
and there was a second, unused `BotConfig` model in `waffy/config/models.py`
with the mismatched `[bot]` field names (that model has since been deleted —
it had no callers anywhere and existed only as a stale echo of the wrong
section name). This meant `config/default_config.toml`'s bot-detection
values were silently ignored at load time and `BotDetectionConfig()`'s
hardcoded defaults were always used regardless of the TOML file. The TOML
section was renamed to `[bot_detection]` with field names corrected to match
`BotDetectionConfig` exactly (`honeypot_path: str` → `honeypot_endpoints:
list[str]`, plus the previously-absent `known_bad_tls_fingerprints` key),
and `waffy/config/__init__.py` now exports `BotDetectionConfig` instead of
the deleted dead class. Two regression tests load through the real
`load_config()` → TOML path (not by constructing `BotDetectionConfig`
directly, which would pass even with a wrong section name) with values that
deliberately differ from the class's hardcoded defaults, so a reintroduced
section-name mismatch fails the test rather than silently passing.

**New gap found while fixing the above, not fixed (explicitly out of
prompts/11's scope — that task was bot-config-only), flagged here for a
future task**: the exact same class of bug also affects rate limiting —
`config/default_config.toml` has a `[ratelimit]` section, but
`WaffyConfig.rate_limiting`'s Pydantic field name is `rate_limiting`, and the
TOML's field names (`requests_per_minute_ip`, `requests_per_minute_session`,
`requests_per_minute_global`) don't match `RateLimitConfig`'s
(`requests_per_ip_per_minute`, `requests_per_session_per_minute`,
`global_requests_per_minute`; `requests_per_route_per_minute` is missing
from the TOML entirely). Today, `config/default_config.toml`'s rate-limit
values are silently ignored at load time exactly like the bot-detection
values were. Separately (lower severity — no wrong name, just no TOML
surface at all yet): `http_limits`, `cookie_security`, `credential_stuffing`,
and `csrf` have no corresponding section in `config/default_config.toml`, so
they always load from Pydantic defaults regardless of what an operator might
try to configure for them. None of this was touched by prompts/11.

## SSRF signature detection (Step B1)

**Gap this closes**: `docs/MASTER_SPEC.md` §1 lists SSRF as an in-scope
attack class, but before this task no `ssrf` category existed anywhere —
not in `SignatureCategory`, not in `config/rules/seed_rules.toml`, not in
`config/default_config.toml`'s `enabled_categories`. This was a real
detection gap, not just a labeling gap: an SSRF payload (e.g. a URL
parameter pointed at `169.254.169.254`) would pass through the signature
engine unflagged.

**Four rules, deliberately split by confidence level** (`config/rules/seed_rules.toml`):

- `WAFFY-SSRF-001` (PL1, weight 35): cloud instance metadata endpoint
  targeting — `169.254.169.254` (AWS + Azure IMDS share this address),
  `metadata.google.internal` (GCP's metadata hostname), `100.100.100.200`
  (Alibaba Cloud). No legitimate application parameter value should ever
  contain one of these, so this is the highest-confidence, highest-weight
  SSRF rule and needs no scheme-prefix requirement.
- `WAFFY-SSRF-002` (PL1, weight 25): loopback/RFC1918 internal-network
  targeting, but *only* when it appears behind an absolute URL scheme
  (`http(s)://`, `ftp://`, `gopher://`, `dict://`) — e.g.
  `url=http://127.0.0.1:6379/`. Bare mentions of an RFC1918 address with no
  scheme prefix are deliberately **not** matched by this rule: a bare
  `192.168.1.5` appearing in a request body is plausibly legitimate
  application data (e.g. a network-device-configuration UI), so requiring
  URL-scheme context is a precision tradeoff, not an oversight.
- `WAFFY-SSRF-003` (PL1, weight 20): dangerous `gopher://`/`dict://`
  schemes, which enable protocol smuggling in server-side fetch parameters
  (the classic Redis-via-gopher SSRF chain). `file://` is intentionally
  **not** duplicated here — it's already covered by the existing
  `WAFFY-LFIRFI-001` pattern; this rule only adds the two schemes LFI/RFI
  didn't already cover.
- `WAFFY-SSRF-004` (**PL2+ only**, weight 8 — lowest of the four): a
  fetch-prone parameter *name* (`url`, `uri`, `callback`, `webhook`, `feed`,
  `target`, `dest`, `redirect`, `proxy`) combined with a value that looks
  like an absolute URL. Gated to PL2+ specifically because the spec called
  out the false-positive risk directly: plenty of legitimate applications
  have a `url=` or `redirect=` parameter that takes an absolute URL for
  entirely benign reasons (an image CDN, a post-login redirect target).
  Name alone is never sufficient — see the engine change below — and this
  rule is the lowest-weight of the four precisely because it's the
  lowest-confidence signal.

**Engine change required to support rule 004** (`waffy/detection/signatures/schema.py`,
`waffy/detection/signatures/engine.py`): before this task, `SignatureDefinition`
had no way to condition a match on the parameter/field *name*, only its
*value* — `SignatureEngine._extract_target_strings()` already produced
`(target_field, field_name, value)` triples internally, but `field_name` was
only ever attached to the resulting `SignatureMatch` for reporting, never
consulted during matching. Added an optional `field_name_pattern: str | None`
to `SignatureDefinition` (`None` by default — every pre-existing signature's
behavior is unchanged); when set, `CompiledSignature` compiles it as a
second regex, and `SignatureEngine.match()` skips a target item whose
`field_name` doesn't match it before ever running the value regex. This is
a small, additive, backward-compatible change (no existing rule sets it) that
lets a signature combine a name signal with a value signal instead of
approximating one alone with a single regex.

**Measured results** (`uv run python scripts/attack-lab/run_corpus.py --report`,
6 new SSRF payloads added to `scripts/attack-lab/corpus.py`: AWS/Azure
metadata IP, GCP metadata hostname, loopback-with-scheme, RFC1918-with-scheme,
gopher-scheme Redis smuggling, and a PL2-only param-name+URL case):

| Level | SSRF TP rate | Benign FP rate |
|---|---|---|
| PL1 | 83.33% (5/6) — the PL2-gated case correctly does not fire | 0.00% (0/7), unchanged |
| PL2 | 100.00% (6/6) | 0.00% (0/7), unchanged |
| PL3 | 100.00% (6/6) | 0.00% (0/7), unchanged |
| PL4 | 100.00% (6/6) | 0.00% (0/7), unchanged |

The PL1→PL2 jump from 83.33% to 100.00% is by design — it is the
`WAFFY-SSRF-004` gate turning on, exactly as the false-positive-avoidance
constraint intended, not a bug being fixed between runs. No other
category's true-positive or false-positive numbers changed as a result of
this task (verified by re-running the full report, not just the SSRF row).

**Unit test coverage** (`tests/unit/test_detection_engine.py`): SSRF
true/false-positive cases added to the existing multi-category test, plus a
dedicated `test_ssrf_param_name_heuristic_is_paranoia_gated_and_name_aware`
proving `WAFFY-SSRF-004` requires *both* signals (name-match-only and
value-match-only cases both must not trigger it) and stays off at PL1.

**Scope not covered**: `enabled_categories`/`rules_dir` in
`DetectionConfig` remain pre-existing, declared-but-unconsumed config
fields (confirmed by grep — nothing in `waffy/detection/` reads either one;
`load_all_rules_from_dir()` loads every `.toml` file in a directory
unconditionally, with no category-based filtering at all). `"ssrf"` was
added to `enabled_categories` in `config/default_config.toml` per this
task's acceptance criteria, for documentation/future-wiring consistency
with every other category already listed there, but this addition has the
same no-op-today status as the other ten entries already in that list —
not a new or SSRF-specific gap.
