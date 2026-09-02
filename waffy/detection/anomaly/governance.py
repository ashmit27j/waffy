"""waffy/detection/anomaly/governance.py — human-approval gate for anomaly
baseline model promotion.

Per prompts/10 and MASTER_SPEC.md §11's "learning mode, distinct from SHADOW
enforcement mode" language: a newly trained Isolation Forest baseline must
never silently become the model ``AnomalyScorer`` scores live traffic
against. Without this gate, an attacker who can shape traffic during a
route's learning-mode window could gradually desensitize what counts as
"normal" with zero operator visibility into the transition -- baseline
poisoning.

Mechanism, deliberately simple and file-based (matching ``baseline.py`` and
``scorer.py``, which are already pure-disk, no database):

- ``BaselineBuilder.train_and_save`` is unchanged and still writes wherever
  it's told (its own unit tests keep asserting "given a directory, produces
  an immediately-scorable model" as a pure trainer contract).
- This module's ``ModelGovernanceService`` is the piece that decides *where*
  training output lands operationally: a ``candidates/`` subdirectory of the
  scorer's real ``model_dir``. ``AnomalyScorer.load_models()`` uses a
  non-recursive ``Path.glob("*.meta.json")`` against ``model_dir``, so files
  in ``model_dir/candidates/`` are invisible to it automatically -- a
  candidate cannot become active by accident.
- ``promote()`` is the only path that moves a candidate's files into
  ``model_dir`` proper, replacing that route's prior active model. Nothing
  else does this. No automated drift detection auto-approves or
  auto-rejects a candidate; this is a human-review-only gate.
"""

from __future__ import annotations

import logging
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from waffy.core.models.domain import HttpRequestRecord, ModelMetadata
from waffy.detection.anomaly.baseline import BaselineBuilder

logger = logging.getLogger("waffy.detection.anomaly.governance")


class ModelGovernanceService:
    """Promotion gate between newly trained candidate models and the active
    model directory an ``AnomalyScorer`` reads from.
    """

    def __init__(self, model_dir: str | Path) -> None:
        self.model_dir = Path(model_dir)
        self.candidates_dir = self.model_dir / "candidates"
        self.model_dir.mkdir(parents=True, exist_ok=True)
        self.candidates_dir.mkdir(parents=True, exist_ok=True)

    def train_candidate(
        self,
        builder: BaselineBuilder,
        route_id: str,
        corpus: Sequence[tuple[HttpRequestRecord, bytes]],
        version: str | None = None,
    ) -> ModelMetadata | None:
        """Train a new candidate model for *route_id* into the candidates
        directory -- never directly into ``model_dir``. Returns None if the
        corpus is below ``builder.min_sample_size`` (same fallback
        ``BaselineBuilder.train_and_save`` already enforces).
        """
        resolved_version = version or datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
        return builder.train_and_save(
            route_id, corpus, self.candidates_dir, version=resolved_version
        )

    def list_candidates(self) -> list[ModelMetadata]:
        """List every pending candidate model's metadata, most-recently
        trained first. Corrupted candidate metadata is skipped, not raised
        -- a bad file must never break the whole listing.
        """
        metas: list[ModelMetadata] = []
        for meta_path in self.candidates_dir.glob("*.meta.json"):
            try:
                metas.append(ModelMetadata.model_validate_json(meta_path.read_text("utf-8")))
            except Exception as e:
                logger.warning("Skipping unreadable candidate metadata '%s': %s", meta_path, e)
        metas.sort(key=lambda m: m.trained_at, reverse=True)
        return metas

    def get_active_metadata(self, route_id: str) -> ModelMetadata | None:
        """Read the currently-active model's metadata for *route_id*, if
        any -- used to compute the operator-facing comparison.
        """
        for meta_path in self.model_dir.glob("*.meta.json"):
            try:
                meta = ModelMetadata.model_validate_json(meta_path.read_text("utf-8"))
            except Exception:
                continue
            if meta.route_id == route_id:
                return meta
        return None

    def compare_to_active(self, candidate: ModelMetadata) -> dict[str, Any]:
        """Basic, non-ML, deterministic comparison of a candidate against
        the currently-active model for the same route -- surfaced to the
        operator so a suspicious retrain (e.g. a big shift in a feature's
        mean, or a suspiciously small sample count) is visible before
        promotion. This is descriptive only; it never auto-rejects.
        """
        active = self.get_active_metadata(candidate.route_id)
        if active is None:
            return {"active_exists": False}

        feature_mean_deltas: dict[str, float] = {}
        for name, stats in candidate.feature_summary.items():
            active_stats = active.feature_summary.get(name)
            if active_stats is not None:
                feature_mean_deltas[name] = stats["mean"] - active_stats["mean"]

        return {
            "active_exists": True,
            "active_version": active.version,
            "active_trained_at": active.trained_at.isoformat(),
            "active_sample_count": active.sample_count,
            "candidate_sample_count": candidate.sample_count,
            "sample_count_delta": candidate.sample_count - active.sample_count,
            "feature_mean_deltas": feature_mean_deltas,
        }

    def _candidate_paths(self, route_id: str, version: str) -> tuple[Path, Path]:
        model_file = self.candidates_dir / f"{route_id}_{version}.joblib"
        meta_file = self.candidates_dir / f"{route_id}_{version}.meta.json"
        return model_file, meta_file

    def promote(self, route_id: str, version: str) -> bool:
        """Approve a candidate: move its files from the candidates directory
        into the active ``model_dir``, replacing any prior active model for
        this route. Returns False (no exception) if no such candidate
        exists -- the caller decides how to surface that.
        """
        model_src, meta_src = self._candidate_paths(route_id, version)
        if not model_src.is_file() or not meta_src.is_file():
            return False

        # A route has exactly one active model at a time.
        for old in self.model_dir.glob(f"{route_id}_*.joblib"):
            old.unlink(missing_ok=True)
        for old in self.model_dir.glob(f"{route_id}_*.meta.json"):
            old.unlink(missing_ok=True)

        model_src.replace(self.model_dir / model_src.name)
        meta_src.replace(self.model_dir / meta_src.name)
        logger.info("Promoted candidate model %s/%s to active.", route_id, version)
        return True

    def reject(self, route_id: str, version: str) -> bool:
        """Reject a candidate: delete its files from the candidates
        directory without ever making it active. Returns False if no such
        candidate exists.
        """
        model_src, meta_src = self._candidate_paths(route_id, version)
        found = model_src.is_file() or meta_src.is_file()
        model_src.unlink(missing_ok=True)
        meta_src.unlink(missing_ok=True)
        if found:
            logger.info("Rejected candidate model %s/%s.", route_id, version)
        return found


__all__ = ["ModelGovernanceService"]
