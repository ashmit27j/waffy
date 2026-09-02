"""waffy/proxy/tls_fingerprint.py — real JA3-style TLS ClientHello fingerprinting.

Two distinct fingerprinting paths are provided here, and CLAUDE.md's honesty
rule requires keeping them clearly distinguished rather than blurring them
together:

1. ``compute_ja3(info)`` — the **canonical JA3 algorithm** (MD5 of
   ``"SSLVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats"``,
   GREASE-filtered per RFC 8701) computed from ``parse_client_hello()``'s
   output over a **real, raw ClientHello byte buffer**. This is byte-perfect
   canonical JA3 when given the real bytes.

2. ``compute_fingerprint_from_ssl_object(ssl_object)`` — a **real-signal, but
   NOT byte-identical to JA3/JA4** fingerprint derived from Python's ``ssl``
   module's POST-handshake ``SSLObject``/``SSLSocket``: negotiated version,
   negotiated cipher, the client's offered-and-server-supported cipher
   intersection (``shared_ciphers()`` — genuinely sourced from the real
   ClientHello via OpenSSL's ``SSL_get_shared_ciphers``, not fabricated), and
   the negotiated ALPN protocol. **Why this path exists**: Python's stdlib
   ``ssl`` module does not expose the raw pre-handshake ClientHello bytes (the
   cipher list as *offered*, the full extension list, GREASE values, etc.)
   through its public API — getting those requires either a parallel,
   hand-rolled TLS listener that captures bytes before the real handshake
   (a materially larger undertaking flagged as a follow-up in
   docs/ARCHITECTURE.md) or a lower-level TLS library dependency. This path
   is what ``waffy/proxy/standalone.py`` wires into production today: a real
   signal from a real completed handshake with a real client, never a
   fabricated placeholder string — just not claimed to be canonical JA3.
   Fingerprints from this path are prefixed ``waffy-tlsfp-v1:`` so they are
   never confused with a canonical JA3/JA4 hash in logs or config.

Both paths degrade gracefully: malformed, truncated, or unavailable input
returns ``None`` and never raises — matching the "absent evidence stays
neutral" rule ``waffy/proxy/plaintext.py`` already documents for the no-JA3
(plaintext mode) case.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import ssl
import struct
from collections import OrderedDict
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger("waffy.proxy.tls_fingerprint")

# RFC 8701 GREASE values: reserved cipher-suite / extension-type IDs a
# well-behaved TLS stack sends to test peer extensibility. Canonical JA3
# excludes these from cipher and extension lists before hashing.
_GREASE_VALUES: frozenset[int] = frozenset(
    (v << 8) | v
    for v in (
        0x0A,
        0x1A,
        0x2A,
        0x3A,
        0x4A,
        0x5A,
        0x6A,
        0x7A,
        0x8A,
        0x9A,
        0xAA,
        0xBA,
        0xCA,
        0xDA,
        0xEA,
        0xFA,
    )
)

_TLS_HANDSHAKE_RECORD_TYPE = 0x16
_CLIENT_HELLO_MSG_TYPE = 0x01
_SUPPORTED_GROUPS_EXT = 10
_EC_POINT_FORMATS_EXT = 11
# TLS record max payload (16384) plus header/handshake-header slack — bounds
# the parse against attacker-controlled input per CLAUDE.md's parsing rules.
_MAX_INPUT_BYTES = 16640


@dataclass(frozen=True)
class ClientHelloInfo:
    """Fields extracted from a raw ClientHello needed to compute JA3."""

    version: int
    cipher_suites: list[int] = field(default_factory=list)
    extensions: list[int] = field(default_factory=list)
    elliptic_curves: list[int] = field(default_factory=list)
    ec_point_formats: list[int] = field(default_factory=list)


def parse_client_hello(data: bytes) -> ClientHelloInfo | None:
    """Parse a raw ClientHello (TLS record header + Handshake message) into
    ``ClientHelloInfo``.

    Defensive, bounds-checked parsing of attacker-controlled bytes: every
    length field is validated against the remaining buffer before use, input
    is capped at ``_MAX_INPUT_BYTES``, and any structural problem (truncated
    buffer, wrong record/message type, an inconsistent length field) returns
    ``None`` rather than raising or looping unboundedly.
    """
    try:
        return _parse_client_hello_unsafe(data[:_MAX_INPUT_BYTES])
    except (struct.error, IndexError, ValueError):
        return None


def _parse_client_hello_unsafe(data: bytes) -> ClientHelloInfo | None:
    if len(data) < 5:
        return None
    record_type = data[0]
    pos = 5  # skip record header: type(1) + version(2) + length(2)
    if record_type != _TLS_HANDSHAKE_RECORD_TYPE:
        return None

    if pos + 4 > len(data):
        return None
    msg_type = data[pos]
    hs_len = int.from_bytes(data[pos + 1 : pos + 4], "big")
    pos += 4
    if msg_type != _CLIENT_HELLO_MSG_TYPE:
        return None
    hs_end = pos + hs_len
    if hs_end > len(data):
        return None

    if pos + 2 > hs_end:
        return None
    client_version = int.from_bytes(data[pos : pos + 2], "big")
    pos += 2

    pos += 32  # random
    if pos > hs_end:
        return None

    if pos + 1 > hs_end:
        return None
    session_id_len = data[pos]
    pos += 1 + session_id_len
    if pos > hs_end:
        return None

    if pos + 2 > hs_end:
        return None
    cs_len = int.from_bytes(data[pos : pos + 2], "big")
    pos += 2
    if cs_len % 2 != 0 or pos + cs_len > hs_end:
        return None
    cipher_suites = [
        int.from_bytes(data[pos + i : pos + i + 2], "big") for i in range(0, cs_len, 2)
    ]
    pos += cs_len

    if pos + 1 > hs_end:
        return None
    comp_len = data[pos]
    pos += 1 + comp_len
    if pos > hs_end:
        return None

    extensions: list[int] = []
    elliptic_curves: list[int] = []
    ec_point_formats: list[int] = []

    if pos + 2 <= hs_end:
        ext_total_len = int.from_bytes(data[pos : pos + 2], "big")
        pos += 2
        ext_end = pos + ext_total_len
        if ext_end > hs_end:
            return None
        while pos + 4 <= ext_end:
            ext_type = int.from_bytes(data[pos : pos + 2], "big")
            ext_len = int.from_bytes(data[pos + 2 : pos + 4], "big")
            pos += 4
            if pos + ext_len > ext_end:
                return None
            ext_data = data[pos : pos + ext_len]
            extensions.append(ext_type)

            if ext_type == _SUPPORTED_GROUPS_EXT and len(ext_data) >= 2:
                list_len = int.from_bytes(ext_data[0:2], "big")
                body = ext_data[2 : 2 + list_len]
                elliptic_curves = [
                    int.from_bytes(body[i : i + 2], "big")
                    for i in range(0, len(body) - (len(body) % 2), 2)
                ]
            elif ext_type == _EC_POINT_FORMATS_EXT and len(ext_data) >= 1:
                list_len = ext_data[0]
                ec_point_formats = list(ext_data[1 : 1 + list_len])

            pos += ext_len

    return ClientHelloInfo(
        version=client_version,
        cipher_suites=cipher_suites,
        extensions=extensions,
        elliptic_curves=elliptic_curves,
        ec_point_formats=ec_point_formats,
    )


def _filter_grease(values: list[int]) -> list[int]:
    return [v for v in values if v not in _GREASE_VALUES]


def compute_ja3(info: ClientHelloInfo) -> str:
    """Compute the canonical JA3 MD5 hash from parsed ClientHello fields.

    ``"{version},{ciphers},{extensions},{curves},{point_formats}"`` with each
    group's values dash-joined and GREASE-filtered from the cipher, extension,
    and curve lists (point formats are single-byte codes, not extension-style
    IDs, and are never GREASE values), then MD5-hashed — the standard
    Salesforce/Trisul JA3 algorithm.
    """
    ja3_str = ",".join(
        [
            str(info.version),
            "-".join(str(c) for c in _filter_grease(info.cipher_suites)),
            "-".join(str(e) for e in _filter_grease(info.extensions)),
            "-".join(str(c) for c in _filter_grease(info.elliptic_curves)),
            "-".join(str(p) for p in info.ec_point_formats),
        ]
    )
    # JA3 is defined as an MD5 hash of the signature string — not a security
    # use of MD5, just the fixed identifier the algorithm specifies.
    return hashlib.md5(ja3_str.encode("ascii")).hexdigest()


def compute_fingerprint_from_ssl_object(ssl_object: ssl.SSLObject | ssl.SSLSocket) -> str | None:
    """Derive a real, ``waffy-tlsfp-v1``-labeled fingerprint from a completed
    handshake's SSLObject/SSLSocket. See module docstring for why this is not
    byte-identical to canonical JA3/JA4. Never raises — any missing or
    unavailable attribute (e.g. handshake not yet complete, non-TLS
    transport) degrades to ``None``, matching the "absent evidence stays
    neutral" contract the bot engine and plaintext.py already rely on.
    """
    try:
        version = ssl_object.version() or ""
        cipher_info = ssl_object.cipher()
        cipher_name = cipher_info[0] if cipher_info else ""
        try:
            shared = ssl_object.shared_ciphers() or []
        except ValueError:
            # Raised by CPython's ssl module if called before the handshake
            # has completed — a real, expected condition, not a bug.
            shared = []
        shared_names = sorted({c[0] for c in shared})
        try:
            alpn = ssl_object.selected_alpn_protocol() or ""
        except ValueError:
            alpn = ""
        signature = f"{version}|{cipher_name}|{','.join(shared_names)}|{alpn}"
        digest = hashlib.md5(signature.encode("utf-8")).hexdigest()
        return f"waffy-tlsfp-v1:{digest}"
    except Exception:
        # Deliberately broad: this function's entire contract is "never crash
        # request handling because a fingerprint couldn't be computed" — the
        # same fault-tolerance stance waffy/detection/anomaly/scorer.py takes
        # for its own evidence-producing layer.
        logger.debug("TLS fingerprint derivation failed; degrading to None", exc_info=True)
        return None


class TlsFingerprintRegistry:
    """Bounded, in-memory map of ``(peer_ip, peer_port) -> fingerprint`` for
    the lifetime of a TCP connection.

    Populated by a connection-capturing protocol (see
    ``build_ja3_capturing_protocol``) at connection start, consulted by the
    pipeline once per request via a plain ``Callable[[str, int], str | None]``
    (so ``waffy/http/pipeline.py`` never needs to import this proxy-layer
    module directly — it only takes a callable, preserving the one-way
    ``core -> config -> http -> detection -> engine -> enforcement -> proxy``
    dependency flow from CLAUDE.md), and cleared at connection end. Bounded
    LRU eviction protects against unbounded growth under connection churn,
    the same pattern ``waffy/detection/bot/engine.py``'s
    ``TimingRegularityTracker`` already uses.
    """

    def __init__(self, max_entries: int = 10000) -> None:
        self._max_entries = max_entries
        self._entries: OrderedDict[tuple[str, int], str] = OrderedDict()

    def record(self, peer: tuple[str, int], fingerprint: str | None) -> None:
        """Record a fingerprint for a connection's (ip, port). No-op if None."""
        if fingerprint is None:
            return
        if peer in self._entries:
            self._entries.move_to_end(peer)
        elif len(self._entries) >= self._max_entries:
            self._entries.popitem(last=False)
        self._entries[peer] = fingerprint

    def get(self, ip: str, port: int) -> str | None:
        """Look up a fingerprint by (ip, port) — matches ``Callable[[str, int], str | None]``."""
        return self._entries.get((ip, port))

    def forget(self, peer: tuple[str, int]) -> None:
        """Remove a connection's fingerprint (call on connection close)."""
        self._entries.pop(peer, None)

    def __len__(self) -> int:
        return len(self._entries)


def build_ja3_capturing_protocol(
    registry: TlsFingerprintRegistry,
) -> type[asyncio.Protocol] | None:
    """Return a uvicorn ``H11Protocol`` subclass that records a real,
    handshake-derived TLS fingerprint into *registry* on every new
    connection, or ``None`` if uvicorn's internal protocol class can't be
    imported.

    Degrades gracefully by design: if this returns ``None``, standalone TLS
    mode still runs correctly via uvicorn's default protocol — it just runs
    without TLS fingerprint capture, exactly like plaintext mode already
    documents for the no-JA3 case. The override only *adds* behavior after
    delegating to the real implementation via ``super()`` — it never changes
    HTTP parsing/handling, so it carries none of the correctness risk a
    reimplemented HTTP layer would.
    """
    try:
        from uvicorn.protocols.http.h11_impl import H11Protocol
    except ImportError:
        logger.warning(
            "uvicorn.protocols.http.h11_impl.H11Protocol not importable; "
            "TLS fingerprint capture disabled for this listener (neutral, not fatal)."
        )
        return None

    class Ja3CapturingH11Protocol(H11Protocol):
        """H11Protocol that also records a TLS fingerprint per connection."""

        def connection_made(self, transport: asyncio.Transport) -> None:
            super().connection_made(transport)
            try:
                ssl_object = transport.get_extra_info("ssl_object")
                peername = transport.get_extra_info("peername")
                if ssl_object is not None and peername is not None:
                    fingerprint = compute_fingerprint_from_ssl_object(ssl_object)
                    registry.record((peername[0], peername[1]), fingerprint)
            except Exception:
                logger.debug("TLS fingerprint capture failed for a connection", exc_info=True)

        def connection_lost(self, exc: Exception | None) -> None:
            transport = getattr(self, "transport", None)
            try:
                peername = transport.get_extra_info("peername") if transport else None
                if peername is not None:
                    registry.forget((peername[0], peername[1]))
            finally:
                super().connection_lost(exc)

    return Ja3CapturingH11Protocol


TlsFingerprintLookup = Callable[[str, int], "str | None"]


def build_standalone_uvicorn_config(
    app: Any,
    ssl_context: ssl.SSLContext,
    *,
    host: str = "0.0.0.0",
    port: int = 443,
    fingerprint_registry: TlsFingerprintRegistry | None = None,
) -> Any:
    """Build the ``uvicorn.Config`` for standalone TLS mode, wiring in the
    real ``ssl.SSLContext`` from ``build_ssl_context()`` and, when a registry
    is supplied, real TLS ClientHello-derived fingerprint capture.

    Returns ``uvicorn.Config`` (typed ``Any`` here to avoid an unconditional
    top-level ``import uvicorn`` in this module — uvicorn is already a
    project dependency, imported lazily to keep this module importable in
    contexts that don't need a real server, e.g. pure unit tests of
    ``compute_ja3``/``parse_client_hello``).
    """
    import uvicorn

    registry = fingerprint_registry or TlsFingerprintRegistry()
    http_protocol = build_ja3_capturing_protocol(registry) or "auto"
    return uvicorn.Config(
        app=app,
        host=host,
        port=port,
        ssl_context_factory=lambda _cfg, _default: ssl_context,
        http=http_protocol,
        lifespan="off",
    )


__all__ = [
    "ClientHelloInfo",
    "TlsFingerprintLookup",
    "TlsFingerprintRegistry",
    "build_ja3_capturing_protocol",
    "build_standalone_uvicorn_config",
    "compute_fingerprint_from_ssl_object",
    "compute_ja3",
    "parse_client_hello",
]
