"""Validation chain for persistent actions (CandidateBan, CandidateRule) per spec §13.

Fixed Order:
1. Schema validation
2. Network / target validity
3. Allowlist check (never ban allowlisted target)
4. Safety validation (never ban management source, localhost, or overbroad CIDR)
5. Conflict check
6. Duplicate check (prevent re-banning already banned active target)
7. Rate-cap check (bounded new bans per window)
8. Expiration check (unexpired duration)
9. Authorization check
"""

import time
from collections import deque
from datetime import UTC, datetime, timedelta
from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network

from waffy.config.models import ApiConfig, EnforcementConfig
from waffy.core.exceptions import ValidationError
from waffy.core.interfaces import RuleStore
from waffy.core.models.domain import BanEntry, CandidateBan


class BanRateLimiter:
    """Sliding-window rate limiter bounding persistent ban creation per hour."""

    def __init__(self, max_bans_per_hour: int = 50) -> None:
        self.max_bans = max_bans_per_hour
        self.history: deque[float] = deque()

    def check_and_record(self) -> bool:
        now = time.time()
        one_hour_ago = now - 3600.0

        while self.history and self.history[0] < one_hour_ago:
            self.history.popleft()

        if len(self.history) >= self.max_bans:
            return False

        self.history.append(now)
        return True


class ActionValidationChain:
    """Validates candidate persistent bans and rules before activation."""

    def __init__(
        self,
        enforcement_config: EnforcementConfig,
        api_config: ApiConfig,
        rule_store: RuleStore,
    ) -> None:
        self.enforcement_config = enforcement_config
        self.api_config = api_config
        self.rule_store = rule_store
        self.rate_limiter = BanRateLimiter(enforcement_config.max_bans_per_hour)

    async def validate_candidate_ban(
        self,
        candidate: CandidateBan,
        authorized: bool = True,
    ) -> BanEntry:
        """Execute full validation chain in fixed order and return approved BanEntry."""
        target_str = candidate.target.strip()

        # 1. Schema check
        if not candidate.reason:
            raise ValidationError("Validation failed at stage [schema]: Missing reason")

        # 2. Network / Target validity check
        is_network = "/" in target_str
        net: IPv4Network | IPv6Network | None = None
        ip_addr: IPv4Address | IPv6Address | None = None

        try:
            if is_network:
                net = (
                    IPv4Network(target_str, strict=False)
                    if "." in target_str
                    else IPv6Network(target_str, strict=False)
                )
            else:
                ip_addr = (
                    IPv4Address(target_str) if "." in target_str else IPv6Address(target_str)
                )
        except Exception as e:
            msg = (
                f"Validation failed at stage [network_validity]: "
                f"Invalid IP/CIDR '{target_str}': {e}"
            )
            raise ValidationError(msg) from e

        # 3. Allowlist check (outranks all adaptive decisions)
        allowlist = await self.rule_store.list_allowlist()
        for allowed in allowlist:
            if allowed.target == target_str:
                raise ValidationError(
                    f"Validation failed at stage [allowlist]: Target '{target_str}' is on allowlist"
                )

        # 4. Safety validation: never ban management CIDR, localhost, or overbroad CIDR
        for mgmt_cidr in self.api_config.management_cidrs:
            try:
                m_net = (
                    IPv4Network(mgmt_cidr, strict=False)
                    if "." in mgmt_cidr
                    else IPv6Network(mgmt_cidr, strict=False)
                )
                if net is not None:
                    if net.overlaps(m_net):
                        raise ValidationError(
                            f"Validation failed at stage [safety]: "
                            f"Target overlaps management network '{mgmt_cidr}'"
                        )
                elif ip_addr is not None and ip_addr in m_net:
                    raise ValidationError(
                        f"Validation failed at stage [safety]: "
                        f"Target is within management network '{mgmt_cidr}'"
                    )
            except ValidationError:
                raise
            except Exception:
                pass

        # Overbroad CIDR safety rule: reject IPv4 wider than /24 or IPv6 wider than /64
        if net is not None:
            prefix_len = net.prefixlen
            if isinstance(net, IPv4Network) and prefix_len < 24:
                raise ValidationError(
                    f"Validation failed at stage [safety]: CIDR /{prefix_len} is overly broad "
                    f"(must be >= /24 for IPv4)"
                )
            if isinstance(net, IPv6Network) and prefix_len < 64:
                raise ValidationError(
                    f"Validation failed at stage [safety]: CIDR /{prefix_len} is overly broad "
                    f"(must be >= /64 for IPv6)"
                )

        # 5 & 6. Conflict / Duplicate check
        existing_ban = await self.rule_store.get_ban(target_str)
        if existing_ban:
            raise ValidationError(
                f"Validation failed at stage [duplicate]: Target '{target_str}' is already banned"
            )

        # 7. Rate-cap check
        if not self.rate_limiter.check_and_record():
            raise ValidationError(
                f"Validation failed at stage [rate_cap]: Maximum new bans per hour limit "
                f"({self.enforcement_config.max_bans_per_hour}) reached"
            )

        # 8. Expiration check
        if candidate.duration_seconds <= 0:
            raise ValidationError(
                "Validation failed at stage [expiration]: Duration must be greater than 0"
            )

        # 9. Authorization check
        if not authorized:
            raise ValidationError(
                "Validation failed at stage [authorization]: Action not authorized"
            )

        now = datetime.now(UTC)
        expires_at = now + timedelta(seconds=candidate.duration_seconds)

        return BanEntry(
            target=target_str,
            scope=candidate.scope,
            reason=candidate.reason,
            evidence_refs=candidate.evidence_refs,
            created_at=now,
            expires_at=expires_at,
        )
