"""Anomaly detection module."""

from waffy.detection.anomaly.baseline import BaselineBuilder
from waffy.detection.anomaly.features import (
    FEATURE_NAMES,
    FEATURE_SCHEMA_VERSION,
    RequestFeatureVector,
    calculate_shannon_entropy,
    extract_features,
)
from waffy.detection.anomaly.scorer import AnomalyScorer

__all__ = [
    "FEATURE_NAMES",
    "FEATURE_SCHEMA_VERSION",
    "AnomalyScorer",
    "BaselineBuilder",
    "RequestFeatureVector",
    "calculate_shannon_entropy",
    "extract_features",
]
