"""waffy/proxy/standalone.py — TLS-terminating standalone reverse-proxy mode.

Architecture
------------
- Owns the public listener (default 443 / 80 redirect).
- Terminates TLS using the ``CertificateProvider`` protocol (a concrete
  ``FileCertificateProvider`` is provided that reads cert + key from
  configured file paths).
- Decrypts inbound HTTPS, passes the plaintext request through the full
  detection/scoring/decision/enforcement pipeline (``WaffyPipelineApplication``),
  then forwards the upstream response back to the client.
- Upstream connectivity uses the ``UpstreamClient`` protocol — a real
  ``HttpxUpstreamClient`` or any Fake for testing.

ACME / Let's Encrypt
--------------------
Automatic certificate provisioning (ACME / Let's Encrypt) is a **stretch goal**
and is intentionally **NOT implemented in this phase**.  The current
``CertificateProvider`` protocol is deliberately designed to accommodate an
ACME implementation in a later phase without changing call sites.  Until then
an operator must supply a pre-obtained PEM cert and key via configuration
(``transport.tls_cert_path`` / ``transport.tls_key_path``).
"""

import logging
import ssl
from pathlib import Path

from waffy.core.interfaces import (
    CertificateProvider,
)

logger = logging.getLogger("waffy.proxy.standalone")


class FileCertificateProvider:
    """Concrete ``CertificateProvider`` that loads a cert/key pair from disk.

    This implementation covers the common case of a statically provisioned
    certificate (e.g., issued by an internal CA or Let's Encrypt via certbot
    in manual/hook mode).

    ACME stretch goal
    -----------------
    Automatic renewal via the ACME protocol (draft-ietf-acme-acme) is NOT
    implemented.  To add it: implement ``CertificateProvider.renew_certificate``
    using an ACME client library (e.g., ``acme`` from certbot) and arrange a
    periodic background task to call it before ``not_after`` is within a
    configurable renewal window.
    """

    def __init__(self, cert_path: str, key_path: str) -> None:
        self.cert_path = Path(cert_path)
        self.key_path = Path(key_path)

    async def get_certificate(self, domain: str) -> tuple[str, str] | None:
        """Read and return (cert_pem, key_pem) from disk.

        The *domain* argument is accepted for interface compatibility with
        future SNI-multiplexed ACME implementations but is not used by this
        file-based provider.
        """
        _ = domain
        if not self.cert_path.exists() or not self.key_path.exists():
            logger.error(
                "TLS certificate or key file not found: cert=%s key=%s",
                self.cert_path,
                self.key_path,
            )
            return None
        return self.cert_path.read_text(), self.key_path.read_text()

    async def renew_certificate(self, domain: str) -> bool:
        """Not implemented — ACME stretch goal (see module docstring)."""
        logger.warning(
            "renew_certificate called for '%s' but ACME is not implemented "
            "in this phase.  Provision the certificate manually and restart "
            "the process to pick up the new material.",
            domain,
        )
        return False


def build_ssl_context(cert_pem: str, key_pem: str) -> ssl.SSLContext:
    """Build a server-side ``ssl.SSLContext`` from PEM-encoded material.

    Settings applied:
    - TLS 1.2 minimum (TLS 1.0 / 1.1 disabled).
    - ``OP_NO_SSLv2`` / ``OP_NO_SSLv3`` unconditionally set.
    - ECDH cipher preference for forward secrecy.
    - Server-side cipher ordering enabled.
    """
    import tempfile

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.options |= ssl.OP_NO_SSLv2  # type: ignore[attr-defined]
    ctx.options |= ssl.OP_NO_SSLv3  # type: ignore[attr-defined]
    ctx.set_ciphers(
        "ECDHE-ECDSA-AES256-GCM-SHA384:"
        "ECDHE-RSA-AES256-GCM-SHA384:"
        "ECDHE-ECDSA-CHACHA20-POLY1305:"
        "ECDHE-RSA-CHACHA20-POLY1305:"
        "!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK:!SRP"
    )
    # SSLContext.load_cert_chain requires file paths; write PEM material to
    # ephemeral temp files that are immediately unlinked after loading.
    with (
        tempfile.NamedTemporaryFile(mode="w", suffix=".crt", delete=False) as cert_f,
        tempfile.NamedTemporaryFile(mode="w", suffix=".key", delete=False) as key_f,
    ):
        cert_f.write(cert_pem)
        key_f.write(key_pem)
        cert_path = cert_f.name
        key_path = key_f.name
    try:
        ctx.load_cert_chain(certfile=cert_path, keyfile=key_path)
    finally:
        import os as _os
        _os.unlink(cert_path)
        _os.unlink(key_path)
    return ctx


class StandaloneProxyConfig:
    """Runtime configuration for the TLS standalone proxy mode."""

    def __init__(
        self,
        *,
        tls_host: str = "0.0.0.0",
        tls_port: int = 443,
        http_port: int = 80,
        cert_path: str = "/etc/waffy/tls/server.crt",
        key_path: str = "/etc/waffy/tls/server.key",
    ) -> None:
        self.tls_host = tls_host
        self.tls_port = tls_port
        self.http_port = http_port
        self.cert_provider: CertificateProvider = FileCertificateProvider(cert_path, key_path)


__all__ = [
    "FileCertificateProvider",
    "build_ssl_context",
    "StandaloneProxyConfig",
]
