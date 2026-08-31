"""Mode-aware decision engine with evidence-maturity invariant.

Evidence-Maturity Invariant (spec §12):
A BLOCK or top-of-ladder CHALLENGE requires:
(a) High-confidence Paranoia-1 signature match in historically low-FP category
    (SQLi, CMDi, Path Traversal, SSTI).
(b) Multiple independent corroborated evidence categories (e.g. signature + anomaly).
(c) Recurring ambiguous reading from the same source across N consecutive requests.

Single weak/ambiguous signals alone cap at LOG or CHALLENGE, never BLOCK.
"""

import logging
from collections import OrderedDict
from typing import Any

from waffy.config.models import EnforcementConfig, EngineConfig
from waffy.core.enums import (
    EnforcementAction,
    EnforcementMode,
    SignatureCategory,
    ThreatLevel,
)
from waffy.core.models.domain import Decision, RequestAssessment

logger = logging.getLogger("waffy.engine.decision")

HIGH_CONFIDENCE_CATEGORIES = {
    SignatureCategory.SQLI,
    SignatureCategory.COMMAND_INJECTION,
    SignatureCategory.PATH_TRAVERSAL,
    SignatureCategory.SSTI,
    SignatureCategory.DESERIALIZATION,
    SignatureCategory.LFI_RFI,
}


class ConsistencyTracker:
    """LRU-bounded per-source tracker for recurring ambiguous signals."""

    def __init__(self, capacity: int = 1000) -> None:
        self.capacity = capacity
        self._counts: OrderedDict[str, int] = OrderedDict()

    def record_and_get_count(self, source_ip: str) -> int:
        count = self._counts.get(source_ip, 0) + 1
        self._counts[source_ip] = count
        self._counts.move_to_end(source_ip)

        if len(self._counts) > self.capacity:
            self._counts.popitem(last=False)
        return count

    def reset(self, source_ip: str) -> None:
        if source_ip in self._counts:
            del self._counts[source_ip]


class DecisionEngine:
    """Computes EnforcementAction and Decision from RequestAssessment."""

    def __init__(
        self,
        engine_config: EngineConfig,
        enforcement_config: EnforcementConfig,
    ) -> None:
        self.engine_config = engine_config
        self.enforcement_config = enforcement_config
        self.consistency_tracker = ConsistencyTracker(capacity=5000)

    def check_evidence_maturity(self, assessment: RequestAssessment) -> tuple[bool, str]:
        """Evaluate whether assessment satisfies the Evidence-Maturity Invariant for BLOCK."""
        # Condition (a): High-confidence low-FP category match
        for sm in assessment.signature_matches:
            if sm.category in HIGH_CONFIDENCE_CATEGORIES:
                return True, f"High-confidence signature match ({sm.category.value})"

        # Condition (b): Multiple independent evidence categories corroborating
        categories_present = 0
        if assessment.signature_matches:
            categories_present += 1
        if assessment.positive_violations:
            categories_present += 1
        if assessment.anomaly_evidence and assessment.anomaly_evidence.is_anomaly:
            categories_present += 1
        if assessment.bot_assessment and assessment.bot_assessment.is_bot:
            categories_present += 1
        if assessment.rate_limit_state and assessment.rate_limit_state.tripped:
            categories_present += 1

        if categories_present >= 2:
            return True, f"Multiple corroborating evidence categories ({categories_present})"

        # Condition (c): Recurring ambiguous reading from same source
        recur_count = self.consistency_tracker.record_and_get_count(assessment.client_ip)
        if recur_count >= self.engine_config.consecutive_escalation_count:
            return True, f"Recurring elevated signal from source ({recur_count} occurrences)"

        return False, "Single weak/ambiguous signal fails evidence-maturity invariant"

    def decide(
        self,
        assessment: RequestAssessment,
        is_allowlisted: bool = False,
    ) -> Decision:
        """Compute Decision considering threat level, allowlist, evidence maturity, and mode."""
        reasons: list[str] = []

        # Invariant 1: Allowlist unconditionally outranks all adaptive decisions
        if is_allowlisted:
            return Decision(
                request_id=assessment.request_id,
                action=EnforcementAction.ALLOW,
                mode=self.enforcement_config.mode,
                threat_level=assessment.threat_level,
                reasons=["Allowlisted source IP outranks all detection scores unconditionally"],
                evidence_summary={
                    "allowlist_override": True,
                    "total_score": assessment.total_score,
                },
            )

        # Base action mapping from threat level and rate limit state
        if assessment.rate_limit_state and assessment.rate_limit_state.tripped:
            base_action = EnforcementAction.RATE_LIMIT
        elif assessment.threat_level in (ThreatLevel.CRITICAL, ThreatLevel.HIGH):
            base_action = EnforcementAction.BLOCK
        elif assessment.threat_level == ThreatLevel.MEDIUM:
            base_action = EnforcementAction.CHALLENGE
        elif assessment.threat_level == ThreatLevel.LOW and assessment.total_score > 0:
            base_action = EnforcementAction.LOG
        else:
            base_action = EnforcementAction.ALLOW

        # Invariant 2: Evidence-maturity check for BLOCK actions
        if base_action == EnforcementAction.BLOCK:
            mature, reason_desc = self.check_evidence_maturity(assessment)
            reasons.append(reason_desc)
            if not mature:
                # Downgrade to next mildest action (CHALLENGE)
                logger.info(
                    "Downgrading BLOCK to CHALLENGE for request %s: %s",
                    assessment.request_id,
                    reason_desc,
                )
                base_action = EnforcementAction.CHALLENGE
        elif base_action == EnforcementAction.RATE_LIMIT:
            scope_name = (
                assessment.rate_limit_state.scope if assessment.rate_limit_state else "unknown"
            )
            reasons.append(f"Rate limit tripped on scope '{scope_name}'")
        else:
            reasons.append(f"Score {assessment.total_score:.1f} mapped to {base_action.value}")

        # Mode Branching
        mode = self.enforcement_config.mode
        if mode == EnforcementMode.SHADOW:
            reasons.append("SHADOW mode active: logging proposed action without inline enforcement")
        elif mode == EnforcementMode.ASSISTED and base_action in (
            EnforcementAction.BLOCK,
            EnforcementAction.RATE_LIMIT,
        ):
            reasons.append("ASSISTED mode active: high-risk action queued for operator review")

        is_anomaly = (
            assessment.anomaly_evidence.is_anomaly
            if assessment.anomaly_evidence is not None
            else False
        )
        evidence_summary: dict[str, Any] = {
            "total_score": assessment.total_score,
            "signature_count": len(assessment.signature_matches),
            "positive_violations_count": len(assessment.positive_violations),
            "is_anomaly": is_anomaly,
            "threat_level": assessment.threat_level.value,
        }

        return Decision(
            request_id=assessment.request_id,
            action=base_action,
            mode=mode,
            threat_level=assessment.threat_level,
            reasons=reasons,
            evidence_summary=evidence_summary,
        )
