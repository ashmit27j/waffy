"""waffy/api/auth.py — Authentication and management CIDR guard for waffy-api.

Authentication scheme: Bearer token (``Authorization: Bearer <api_token>``).
The token is compared against ``WaffyConfig.api.api_token`` using a
constant-time comparison to prevent timing-attack token recovery.

Management CIDR guard: every request's source IP must fall within one of the
CIDRs listed in ``WaffyConfig.api.management_cidrs``.  The check is applied
as a FastAPI dependency so it runs before any route handler.

Security notes
--------------
- Both checks are applied together; failing either yields 403 (not 401 for
  CIDR failures, to avoid leaking the existence of the API to non-management
  networks).
- The token is *not* the same as the WAF enforcement allowlist — they are
  entirely separate configs.
- Logging redacts the raw token value.
"""

from __future__ import annotations

import hmac
import ipaddress
import logging
from typing import Annotated

from fastapi import Header, HTTPException, Request, status

from waffy.config.models import WaffyConfig

logger = logging.getLogger("waffy.api.auth")


def parse_management_networks(
    cidrs: list[str],
) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    """Parse management CIDR strings into network objects."""
    nets: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    for cidr in cidrs:
        try:
            if "/" in cidr:
                if "." in cidr:
                    nets.append(ipaddress.IPv4Network(cidr, strict=False))
                else:
                    nets.append(ipaddress.IPv6Network(cidr, strict=False))
            else:
                if "." in cidr:
                    nets.append(ipaddress.IPv4Network(f"{cidr}/32", strict=False))
                else:
                    nets.append(ipaddress.IPv6Network(f"{cidr}/128", strict=False))
        except ValueError:
            logger.warning("Ignoring invalid management CIDR: %s", cidr)
    return nets


# Private aliases kept for internal call-sites.
_parse_management_networks = parse_management_networks


def ip_in_networks(
    ip_str: str,
    networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network],
) -> bool:
    """Return True if *ip_str* is contained in any of *networks*."""
    try:
        addr: ipaddress.IPv4Address | ipaddress.IPv6Address = (
            ipaddress.IPv4Address(ip_str) if "." in ip_str else ipaddress.IPv6Address(ip_str)
        )
    except ValueError:
        return False
    for net in networks:
        try:
            if addr in net:  # type: ignore[operator]
                return True
        except TypeError:
            pass
    return False


# Private alias.
_ip_in_networks = ip_in_networks


class AuthGuard:
    """FastAPI dependency class enforcing token auth + CIDR restriction.

    Parameters
    ----------
    config:
        Root ``WaffyConfig``; reads ``api.api_token`` and
        ``api.management_cidrs``.
    """

    def __init__(self, config: WaffyConfig) -> None:
        self._token = config.api.api_token
        self._networks = _parse_management_networks(config.api.management_cidrs)

    def _check_cidr(self, request: Request) -> None:
        """Raise 403 if the client IP is not in a management CIDR."""
        client_ip: str | None = None
        if request.client:
            client_ip = request.client.host

        # Also honour X-Forwarded-For when the API is behind a trusted proxy.
        forwarded_for = request.headers.get("x-forwarded-for")
        if forwarded_for:
            client_ip = forwarded_for.split(",")[0].strip()

        if client_ip is None or not _ip_in_networks(client_ip, self._networks):
            logger.warning(
                "Management API request from non-management IP: %s",
                client_ip or "unknown",
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access from this source address is not permitted.",
            )

    def _check_token(self, authorization: str | None) -> None:
        """Raise 403 if the bearer token is absent or wrong."""
        expected = f"Bearer {self._token}"
        provided = authorization or ""
        # Use HMAC comparison to prevent timing attacks.
        if not hmac.compare_digest(expected.encode(), provided.encode()):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Invalid or missing API token.",
            )

    async def __call__(
        self,
        request: Request,
        authorization: Annotated[str | None, Header()] = None,
    ) -> None:
        """Enforce CIDR restriction then token check."""
        self._check_cidr(request)
        self._check_token(authorization)


__all__ = [
    "AuthGuard",
    "ip_in_networks",
    "parse_management_networks",
]
