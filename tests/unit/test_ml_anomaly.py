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
from waffy.detection.anomaly.governance import ModelGovernanceService
from waffy.detection.anomaly.scorer import AnomalyScorer


def _benign_corpus(
    n: int, path: str = "/gov", offset: int = 0
) -> list[tuple[HttpRequestRecord, bytes]]:
    corpus: list[tuple[HttpRequestRecord, bytes]] = []
    for i in range(offset, offset + n):
        req = HttpRequestRecord(
            method=HttpMethod.GET,
            path=path,
            query_string=f"q=term{i}&limit=10",
            query_params={"q": [f"term{i}"], "limit": ["10"]},
            client_ip="192.168.1.1",
        )
        corpus.append((req, b""))
    return corpus


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


# ---------------------------------------------------------------------------
# Model governance / promotion gate (prompts/10)
# ---------------------------------------------------------------------------


def test_candidate_model_never_scores_until_promoted(tmp_path: Path) -> None:
    """A freshly trained model must never silently become active."""
    model_dir = tmp_path / "models"
    governance = ModelGovernanceService(model_dir)
    builder = BaselineBuilder(min_sample_size=30, random_state=42)

    meta = governance.train_candidate(
        builder, "route_gov", _benign_corpus(50), version="cand-1"
    )
    assert meta is not None
    # Written into candidates/, never directly into model_dir.
    assert (governance.candidates_dir / "route_gov_cand-1.joblib").is_file()
    assert not (model_dir / "route_gov_cand-1.joblib").is_file()

    # A scorer pointed at model_dir sees nothing for this route -- learning
    # mode / no active model, clean signature-only fallback.
    scorer = AnomalyScorer(model_dir)
    assert "route_gov" not in scorer.models
    req = HttpRequestRecord(method=HttpMethod.GET, path="/gov", client_ip="192.168.1.1")
    assert scorer.score("route_gov", req) is None


def test_candidate_model_metadata_visible_via_list_candidates() -> None:
    """Pending-model visibility: what the management API surfaces to an
    operator for review, per prompts/10's constraints.
    """
    import tempfile

    with tempfile.TemporaryDirectory() as td:
        governance = ModelGovernanceService(Path(td) / "models")
        builder = BaselineBuilder(min_sample_size=30, random_state=42)
        governance.train_candidate(builder, "route_gov", _benign_corpus(40), version="cand-1")

        candidates = governance.list_candidates()
        assert len(candidates) == 1
        cand = candidates[0]
        assert cand.route_id == "route_gov"
        assert cand.version == "cand-1"
        assert cand.sample_count == 40
        # Per-feature summary statistics for operator review.
        assert set(cand.feature_summary.keys()) == set(FEATURE_NAMES)
        for stats in cand.feature_summary.values():
            assert set(stats.keys()) == {"mean", "std", "min", "max"}


def test_promote_makes_candidate_active_and_scorer_reload_picks_it_up(
    tmp_path: Path,
) -> None:
    model_dir = tmp_path / "models"
    governance = ModelGovernanceService(model_dir)
    builder = BaselineBuilder(min_sample_size=30, random_state=42)

    governance.train_candidate(builder, "route_gov", _benign_corpus(50), version="cand-1")
    scorer = AnomalyScorer(model_dir)
    assert "route_gov" not in scorer.models  # still pending

    promoted = governance.promote("route_gov", "cand-1")
    assert promoted

    # Candidate files moved out of candidates/, now the only files in model_dir.
    assert not (governance.candidates_dir / "route_gov_cand-1.joblib").is_file()
    assert (model_dir / "route_gov_cand-1.joblib").is_file()
    assert governance.list_candidates() == []

    # The existing live scorer instance does NOT see it until reload_models()
    # is called (mirrors the promotion endpoint's IPC-triggered reload).
    assert "route_gov" not in scorer.models
    scorer.reload_models()
    assert "route_gov" in scorer.models

    req = HttpRequestRecord(method=HttpMethod.GET, path="/gov", client_ip="192.168.1.1")
    evidence = scorer.score("route_gov", req)
    assert evidence is not None


def test_reject_candidate_discards_without_ever_activating(tmp_path: Path) -> None:
    model_dir = tmp_path / "models"
    governance = ModelGovernanceService(model_dir)
    builder = BaselineBuilder(min_sample_size=30, random_state=42)

    governance.train_candidate(builder, "route_gov", _benign_corpus(50), version="cand-1")
    assert len(governance.list_candidates()) == 1

    rejected = governance.reject("route_gov", "cand-1")
    assert rejected
    assert governance.list_candidates() == []
    # Promoting the now-deleted candidate fails cleanly.
    assert governance.promote("route_gov", "cand-1") is False

    scorer = AnomalyScorer(model_dir)
    assert "route_gov" not in scorer.models


def test_active_model_scores_unaffected_while_candidate_pending(tmp_path: Path) -> None:
    """The currently-active model must keep scoring normally while a new
    candidate for the same route awaits operator review.
    """
    model_dir = tmp_path / "models"
    builder = BaselineBuilder(min_sample_size=30, random_state=42)

    # Directly train an "already active" model straight into model_dir,
    # simulating a route that was promoted in a prior session.
    active_meta = builder.train_and_save("route_gov", _benign_corpus(50), model_dir, version="v1")
    assert active_meta is not None

    scorer = AnomalyScorer(model_dir)
    assert "route_gov" in scorer.models
    req = HttpRequestRecord(method=HttpMethod.GET, path="/gov", client_ip="192.168.1.1")
    baseline_evidence = scorer.score("route_gov", req)
    assert baseline_evidence is not None

    governance = ModelGovernanceService(model_dir)
    governance.train_candidate(
        builder, "route_gov", _benign_corpus(60, offset=1000), version="v2-candidate"
    )

    # Active model keeps scoring identically -- the pending candidate never
    # touched it.
    still_active_evidence = scorer.score("route_gov", req)
    assert still_active_evidence is not None
    assert still_active_evidence.model_version == "v1"
    assert still_active_evidence.anomaly_score == baseline_evidence.anomaly_score

    comparison = governance.compare_to_active(governance.list_candidates()[0])
    assert comparison["active_exists"] is True
    assert comparison["active_version"] == "v1"
    assert comparison["candidate_sample_count"] == 60


def test_promote_nonexistent_candidate_returns_false(tmp_path: Path) -> None:
    governance = ModelGovernanceService(tmp_path / "models")
    assert governance.promote("no_such_route", "v1") is False
    assert governance.reject("no_such_route", "v1") is False
