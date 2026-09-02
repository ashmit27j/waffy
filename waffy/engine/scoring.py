"""Additive scoring engine per spec §12.

Calculates RequestAssessment.total_score from:
- Signature matches (weighted by paranoia level)
- Positive security violations
- Anomaly evidence (when present)
- Rate limit trips & bot scores
- CSRF token violations & credential-stuffing velocity trips

Maps total_score to ThreatLevel (LOW, MEDIUM, HIGH, CRITICAL).
"""

from waffy.config.models import EngineConfig
from waffy.core.enums import ThreatLevel
from waffy.core.models.domain import RequestAssessment


def compute_assessment_score(
    assessment: RequestAssessment,
    config: EngineConfig,
) -> tuple[float, ThreatLevel]:
    """Compute total weighted anomaly score and threat level from collected evidence."""
    total_score = 0.0

    # 1. Signatures
    for sm in assessment.signature_matches:
        # Default weight or paranoia-level specific weight
        total_score += sm.score_weight

    # 2. Positive security violations
    for pv in assessment.positive_violations:
        total_score += pv.score_weight

    # 3. Anomaly evidence
    if assessment.anomaly_evidence and assessment.anomaly_evidence.is_anomaly:
        # Scale by anomaly score factor [0.0 - 1.0] * weight
        total_score += assessment.anomaly_evidence.anomaly_score * config.weight_anomaly

    # 4. Bot assessment (if populated)
    if assessment.bot_assessment and assessment.bot_assessment.is_bot:
        total_score += config.weight_bot

    # 5. Rate limit state (if tripped)
    if assessment.rate_limit_state and assessment.rate_limit_state.tripped:
        total_score += config.weight_rate_limit

    # 6. CSRF token violation (embedded mode, state-changing requests)
    if assessment.csrf_violation:
        total_score += config.weight_csrf_violation

    # 7. Credential stuffing velocity (evidence from prior failed-login history)
    if assessment.credential_stuffing_evidence and assessment.credential_stuffing_evidence.tripped:
        total_score += config.weight_credential_stuffing

    # Threat Level classification
    if total_score >= config.threshold_critical:
        threat_level = ThreatLevel.CRITICAL
    elif total_score >= config.threshold_high:
        threat_level = ThreatLevel.HIGH
    elif total_score >= config.threshold_medium:
        threat_level = ThreatLevel.MEDIUM
    elif total_score >= config.threshold_low:
        threat_level = ThreatLevel.LOW
    else:
        threat_level = ThreatLevel.LOW

    assessment.total_score = total_score
    assessment.threat_level = threat_level
    return total_score, threat_level
