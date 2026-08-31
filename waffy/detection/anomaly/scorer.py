"""Runtime anomaly scoring engine.

Per spec §11 & CLAUDE.md:
- Produces AnomalyEvidence only, never enforcement commands.
- Tolerates missing or corrupted model files with clean fallback (ModelLoadError degrades
  to signature-only scoring).
"""

import json
import logging
from pathlib import Path
from typing import Any

import joblib
import numpy as np

from waffy.core.exceptions import ModelInferenceError, ModelLoadError
from waffy.core.models.domain import AnomalyEvidence, HttpRequestRecord, ModelMetadata
from waffy.detection.anomaly.features import FEATURE_SCHEMA_VERSION, extract_features

logger = logging.getLogger("waffy.detection.anomaly")


class AnomalyScorer:
    """Evaluates requests against route-specific IsolationForest models."""

    def __init__(self, model_dir: str | Path) -> None:
        self.model_dir = Path(model_dir)
        self.models: dict[str, Any] = {}
        self.metadata: dict[str, ModelMetadata] = {}
        self.load_models()

    def load_models(self) -> None:
        """Load all model artifacts and metadata from model_dir with fault tolerance."""
        if not self.model_dir.is_dir():
            logger.info(
                "Model directory '%s' does not exist; operating in signature-only mode.",
                self.model_dir,
            )
            return

        for meta_path in self.model_dir.glob("*.meta.json"):
            try:
                with open(meta_path, encoding="utf-8") as f:
                    meta_dict: dict[str, Any] = json.load(f)
                meta = ModelMetadata.model_validate(meta_dict)

                model_file = meta_path.with_name(f"{meta.route_id}_{meta.version}.joblib")
                if not model_file.is_file():
                    raise ModelLoadError(f"Missing joblib model file for metadata: {model_file}")

                model = joblib.load(model_file)  # type: ignore[reportUnknownMemberType]
                self.models[meta.route_id] = model
                self.metadata[meta.route_id] = meta
                logger.info(
                    "Loaded anomaly model '%s' (version %s) successfully.",
                    meta.route_id,
                    meta.version,
                )
            except Exception as e:
                # Fault tolerance: log degradation event, continue without crashing
                logger.warning(
                    "MODEL_DEGRADATION: Failed to load anomaly model artifact '%s': %s. "
                    "Falling back to signature-only scoring for this route.",
                    meta_path,
                    e,
                )

    def score(
        self,
        route_id: str,
        request: HttpRequestRecord,
        raw_body_bytes: bytes = b"",
    ) -> AnomalyEvidence | None:
        """Compute anomaly score for request against route model if available.

        Returns:
            AnomalyEvidence if a valid model exists for route_id, otherwise None.
        """
        model = self.models.get(route_id)
        meta = self.metadata.get(route_id)
        if model is None or meta is None:
            # Route is in learning mode or has no trained model -> fallback cleanly
            return None

        try:
            vec = extract_features(request, raw_body_bytes)
            X = np.array([vec.to_array()], dtype=np.float64)

            # decision_function: lower score = more abnormal
            # Raw score is typically in [-0.5, 0.5]; map to normalized [0.0, 1.0] anomaly score
            raw_score: float = float(model.decision_function(X)[0])
            # Higher anomaly_score (towards 1.0) means more anomalous
            norm_anomaly_score = max(0.0, min(1.0, 0.5 - raw_score))

            is_anomaly = norm_anomaly_score >= meta.threshold

            return AnomalyEvidence(
                model_id=meta.model_id,
                model_version=meta.version,
                anomaly_score=norm_anomaly_score,
                feature_vector_version=FEATURE_SCHEMA_VERSION,
                is_anomaly=is_anomaly,
                details={
                    "raw_decision_score": raw_score,
                    "normalized_anomaly_score": norm_anomaly_score,
                    "threshold": meta.threshold,
                },
            )
        except Exception as e:
            logger.error("Error during anomaly inference for request %s: %s", request.request_id, e)
            raise ModelInferenceError(f"Anomaly inference failure: {e}") from e
