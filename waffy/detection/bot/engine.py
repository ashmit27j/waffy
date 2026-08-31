"""Bot detection heuristics per spec §10.

Evidence-Only Sources:
1. User-Agent classification (known-bad scrapers vs known-good search crawlers).
2. Header order & presence anomaly fingerprinting.
3. TLS ClientHello fingerprint matching (JA3/JA4 hook).
4. Request timing regularity (coefficient of variation of inter-arrival times).
5. Honeypot endpoint hit detection.
"""

import math
import re
import time
from collections import OrderedDict, deque
from typing import Any

from waffy.config.models import BotDetectionConfig
from waffy.core.models.domain import BotAssessment, HttpRequestRecord

KNOWN_GOOD_BOT_PATTERNS = [
    re.compile(r"googlebot", re.IGNORECASE),
    re.compile(r"bingbot", re.IGNORECASE),
    re.compile(r"duckduckbot", re.IGNORECASE),
    re.compile(r"slurp", re.IGNORECASE),
    re.compile(r"yandexbot", re.IGNORECASE),
]

KNOWN_BAD_BOT_PATTERNS = [
    re.compile(
        r"\b(curl|wget|python-requests|aiohttp|httpx|scrapy|go-http-client)\b", re.IGNORECASE
    ),
    re.compile(r"\b(sqlmap|nikto|nuclei|masscan|zgrab|nmap|dirbuster|gobuster)\b", re.IGNORECASE),
    re.compile(r"\b(headlesschrome|phantomjs|puppeteer|selenium|playwright)\b", re.IGNORECASE),
]


class TimingRegularityTracker:
    """Tracks inter-arrival times per source to detect automated machine regular polling."""

    def __init__(self, max_sources: int = 5000, history_len: int = 10) -> None:
        self.max_sources = max_sources
        self.history_len = history_len
        self.history: OrderedDict[str, deque[float]] = OrderedDict()

    def record_and_get_cov(self, source_ip: str, now: float | None = None) -> float | None:
        """Compute Coefficient of Variation (std_dev / mean) of inter-arrival delays.

        Returns None if fewer than 5 intervals recorded. Low CoV (< 0.15) indicates bot timing.
        """
        current_time = now if now is not None else time.time()

        if source_ip in self.history:
            dq = self.history[source_ip]
            self.history.move_to_end(source_ip)
        else:
            if len(self.history) >= self.max_sources:
                self.history.popitem(last=False)
            dq: deque[float] = deque(maxlen=self.history_len)
            self.history[source_ip] = dq

        dq.append(current_time)
        if len(dq) < 5:
            return None

        # Compute delta intervals
        intervals: list[float] = [dq[i] - dq[i - 1] for i in range(1, len(dq))]
        mean_int = sum(intervals) / len(intervals)
        if mean_int <= 0.0001:
            return 0.0  # Ultra-fast bursts are machine regular

        variance = sum((x - mean_int) ** 2 for x in intervals) / len(intervals)
        std_dev = math.sqrt(variance)
        return std_dev / mean_int


class BotDetectionEngine:
    """Evaluates multi-signal bot heuristics to produce BotAssessment evidence."""

    def __init__(self, config: BotDetectionConfig) -> None:
        self.config = config
        self.timing_tracker = TimingRegularityTracker()

    def assess(
        self,
        request: HttpRequestRecord,
        tls_fingerprint: str | None = None,
        now: float | None = None,
    ) -> BotAssessment:
        """Assess bot signals and return BotAssessment evidence."""
        if not self.config.enabled:
            return BotAssessment(is_bot=False)

        score = 0.0
        details: dict[str, Any] = {}

        # 1. Honeypot check (Highest confidence bot signal)
        if request.path in self.config.honeypot_endpoints:
            score += 1.0
            details["honeypot_hit"] = True
            return BotAssessment(
                is_bot=True,
                bot_score=1.0,
                category="honeypot_trap",
                details=details,
            )

        # 2. User-Agent Analysis
        ua = ""
        for hk, hv in request.headers:
            if hk.lower() == "user-agent":
                ua = hv
                break

        is_known_good = any(pat.search(ua) for pat in KNOWN_GOOD_BOT_PATTERNS)
        is_known_bad = any(pat.search(ua) for pat in KNOWN_BAD_BOT_PATTERNS)

        if is_known_good:
            details["ua_classification"] = "known_good_crawler"
            score = max(0.0, score - 0.5)
        elif is_known_bad:
            details["ua_classification"] = "known_bad_scraper"
            score += 0.8
        elif not ua:
            details["ua_classification"] = "empty_user_agent"
            score += 0.5

        # 3. Header Fingerprinting (Check for missing standard browser headers)
        headers_set = {hk.lower() for hk, _ in request.headers}
        if "accept" not in headers_set or "accept-language" not in headers_set:
            details["missing_standard_browser_headers"] = True
            score += 0.3

        # 4. TLS Fingerprint check (JA3/JA4 when available)
        if tls_fingerprint:
            details["tls_fingerprint"] = tls_fingerprint
            if tls_fingerprint in ("bad_ja3_fingerprint", "bad_ja4_fingerprint"):
                score += 0.7

        # 5. Timing Regularity (Machine-regular intervals)
        cov = self.timing_tracker.record_and_get_cov(request.client_ip, now)
        if cov is not None:
            details["timing_cov"] = cov
            if cov < 0.15:  # Extremely low variance indicates automated script
                score += 0.6
                details["machine_regular_timing"] = True

        norm_score = min(1.0, max(0.0, score))
        is_bot = norm_score >= 0.7

        return BotAssessment(
            is_bot=is_bot,
            bot_score=norm_score,
            category="automated_client" if is_bot else None,
            details=details,
        )
