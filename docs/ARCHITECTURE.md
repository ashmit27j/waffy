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

## Dependency decisions

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

**Follow-up (not done in prompts/04, explicitly out of scope for it)**: a
future task could implement the `MemoryBIO`-based raw-capture listener
described in option (1) above to get byte-perfect canonical JA3 in
production. `parse_client_hello`/`compute_ja3` are already written and
tested against real captured bytes and are ready to be wired to that capture
path the moment it exists — no rework needed on the algorithm side.

**Known-bad fingerprint list**: `config.bot_detection.known_bad_tls_fingerprints`
(`waffy/config/models.py::BotDetectionConfig`) is an empty-by-default,
operator-managed local list — not a live threat-intel feed. Values can be
either canonical JA3 hashes (once the follow-up above exists) or today's
`waffy-tlsfp-v1:`-prefixed values.

**Pre-existing, unrelated gap noticed during this task (not fixed here, out
of scope)**: `config/default_config.toml`'s `[bot]` TOML section doesn't
actually populate `WaffyConfig.bot_detection` — `WaffyConfig.model_validate()`
expects a `[bot_detection]` section name to match the Pydantic field name,
and there's a second, apparently-unused `BotConfig` model in
`waffy/config/models.py` with the mismatched `[bot]` field names. This means
today, `config/default_config.toml`'s bot-detection values are silently
ignored at load time and `BotDetectionConfig()`'s hardcoded defaults are
always used regardless of the TOML file. This predates prompts/04 and is
unrelated to TLS fingerprinting; flagged here for a future config-layer fix
(prompts/07's config-validation-warnings task is the natural place to catch
this class of silently-ignored-section problem).
