"""Bot detection package."""

from waffy.detection.bot.engine import (
    BotDetectionEngine,
    TimingRegularityTracker,
)

__all__ = ["BotDetectionEngine", "TimingRegularityTracker"]
