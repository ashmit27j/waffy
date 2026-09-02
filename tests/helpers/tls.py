"""Shared test helper for generating a throwaway self-signed TLS cert/key pair.

Uses the system ``openssl`` CLI rather than adding a new Python dependency
(e.g. ``cryptography``) purely for test fixtures — per CLAUDE.md, a new
dependency needs explicit justification, and this avoids needing one. Never
commit generated cert/key material; callers pass a pytest ``tmp_path``-style
directory and it is discarded with the test's temp directory.
"""

import shutil
import subprocess
from pathlib import Path


def openssl_available() -> bool:
    """Whether the ``openssl`` CLI is on PATH."""
    return shutil.which("openssl") is not None


def generate_self_signed_cert(directory: Path) -> tuple[Path, Path]:
    """Generate a throwaway self-signed cert/key pair into *directory*.

    Returns (cert_path, key_path). Raises if ``openssl`` is unavailable or
    fails — callers should check ``openssl_available()`` first and skip.
    """
    cert_path = directory / "server.crt"
    key_path = directory / "server.key"
    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-keyout",
            str(key_path),
            "-out",
            str(cert_path),
            "-days",
            "1",
            "-nodes",
            "-subj",
            "/CN=localhost",
            "-addext",
            "subjectAltName=DNS:localhost,IP:127.0.0.1",
        ],
        check=True,
        capture_output=True,
        timeout=30,
    )
    return cert_path, key_path
