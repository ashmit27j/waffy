"""Unit and integration tests for Phase 4 ML anomaly detection layer."""

from pathlib import Path

import pytest

from waffy.core.enums import HttpMethod
from waffy.core.models.domain import HttpRequestRecord
from waffy.detection.anomaly.baseline import BaselineBuilder
from waffy.detection.anomaly.features import (
    FEATURE_NAMES,
    FEATURE_SCHEMA_VERSION,
    calculate_shannon_entropy,
    extract_features,
)
from waffy.detection.anomaly.scorer import AnomalyScorer


def test_shannon_entropy_calculation() -> None:
    assert calculate_shannon_entropy("") == 0.0
    assert calculate_shannon_entropy("aaaaaa") == 0.0
    # Two symbols equally distributed -> 1 bit
    assert pytest.approx(calculate_shannon_entropy("abababab"), 0.01) == 1.0


def test_feature_extractor_deterministic() -> None:
    req = HttpRequestRecord(
        method=HttpMethod.GET,
        path="/api/v1/users",
        query_string="sort=asc&page=1",
        query_params={"sort": ["asc"], "page": ["1"]},
        headers=[("user-agent", "test-agent"), ("accept", "application/json")],
        client_ip="127.0.0.1",
        encoding_layers=2,
    )
    vec1 = extract_features(req)
    vec2 = extract_features(req)

    assert vec1.schema_version == FEATURE_SCHEMA_VERSION
    assert vec1.features == vec2.features
    assert len(vec1.features) == len(FEATURE_NAMES)
    # Check specific hand-calculated indices
    # index 4 is path_depth ("/api/v1/users" -> 3)
    assert vec1.features[4] == 3.0
    # index 11 is encoding_layers -> 2.0
    assert vec1.features[11] == 2.0


def test_minimum_sample_size_enforcement(tmp_path: Path) -> None:
    builder = BaselineBuilder(min_sample_size=20)
    corpus: list[tuple[HttpRequestRecord, bytes]] = []

    for i in range(10):  # 10 samples < 20 min_sample_size
        req = HttpRequestRecord(
            method=HttpMethod.GET,
            path="/items",
            query_string=f"id={i}",
            query_params={"id": [str(i)]},
            client_ip="127.0.0.1",
        )
        corpus.append((req, b""))

    # Should return None and not persist model below threshold
    meta = builder.train_and_save("route_items", corpus, tmp_path)
    assert meta is None
    assert len(list(tmp_path.glob("*.joblib"))) == 0

    # Test Scorer returns None (graceful fallback to signature-only)
    scorer = AnomalyScorer(tmp_path)
    evidence = scorer.score("route_items", corpus[0][0])
    assert evidence is None


def test_anomaly_training_and_scoring(tmp_path: Path) -> None:
    builder = BaselineBuilder(min_sample_size=30, random_state=42)
    corpus: list[tuple[HttpRequestRecord, bytes]] = []

    # Generate 50 typical benign requests
    for i in range(50):
        req = HttpRequestRecord(
            method=HttpMethod.GET,
            path="/api/search",
            query_string=f"q=term{i}&limit=10",
            query_params={"q": [f"term{i}"], "limit": ["10"]},
            client_ip="192.168.1.1",
        )
        corpus.append((req, b""))

    meta = builder.train_and_save("api_search", corpus, tmp_path)
    assert meta is not None
    assert meta.sample_count == 50

    scorer = AnomalyScorer(tmp_path)
    assert "api_search" in scorer.models

    # 1. Typical benign request from distribution
    benign_req = HttpRequestRecord(
        method=HttpMethod.GET,
        path="/api/search",
        query_string="q=term25&limit=10",
        query_params={"q": ["term25"], "limit": ["10"]},
        client_ip="192.168.1.1",
    )
    benign_evidence = scorer.score("api_search", benign_req)
    assert benign_evidence is not None
    assert not benign_evidence.is_anomaly

    # 2. Anomalous request (wildly long query with high entropy & unusual depth)
    anomalous_req = HttpRequestRecord(
        method=HttpMethod.POST,
        path="/api/search/extra/deep/path/segment",
        query_string="evil=" + "X%2F%3D" * 150,
        query_params={"evil": ["X%2F%3D" * 150]},
        parsed_body_summary={"nested": {"field": "A" * 500}},
        client_ip="192.168.1.1",
        encoding_layers=5,
    )
    anomaly_evidence = scorer.score("api_search", anomalous_req, b"A" * 500)
    assert anomaly_evidence is not None

    print(f"\nBenign Anomaly Score: {benign_evidence.anomaly_score:.3f}")
    print(f"Anomalous Request Score: {anomaly_evidence.anomaly_score:.3f}")
    assert anomaly_evidence.anomaly_score > benign_evidence.anomaly_score


def test_missing_or_corrupted_model_degradation(tmp_path: Path) -> None:
    # Write a corrupt meta file pointing to nonexistent joblib
    corrupt_meta = tmp_path / "corrupt_route_1.0.meta.json"
    corrupt_meta.write_text(
        '{"model_id": "corrupt_route", "route_id": "corrupt_route", '
        '"version": "1.0", "sample_count": 100}',
        encoding="utf-8",
    )

    # Scorer should start without crashing and degrade route to signature-only
    scorer = AnomalyScorer(tmp_path)
    assert "corrupt_route" not in scorer.models

    req = HttpRequestRecord(method=HttpMethod.GET, path="/", client_ip="127.0.0.1")
    evidence = scorer.score("corrupt_route", req)
    assert evidence is None
