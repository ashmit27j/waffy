"""Offline / learning-mode baseline builder using scikit-learn Isolation Forest.

Enforces:
- Minimum sample size before persisting a model (otherwise falls back to signature-only).
- Uses canonical feature extraction function.
- Produces versioned ModelMetadata.
"""

from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest

from waffy.core.models.domain import HttpRequestRecord, ModelMetadata
from waffy.detection.anomaly.features import (
    FEATURE_NAMES,
    extract_features,
)


class BaselineBuilder:
    """Builds and persists IsolationForest anomaly detection models for routes."""

    def __init__(
        self,
        min_sample_size: int = 50,
        contamination: float = 0.05,
        random_state: int = 42,
    ) -> None:
        self.min_sample_size = min_sample_size
        self.contamination = contamination
        self.random_state = random_state

    def train_and_save(
        self,
        route_id: str,
        corpus: Sequence[tuple[HttpRequestRecord, bytes]],
        output_dir: str | Path,
        version: str = "1.0",
    ) -> ModelMetadata | None:
        """Train an Isolation Forest model if sample size threshold is met and save artifact."""
        sample_count = len(corpus)
        if sample_count < self.min_sample_size:
            # Enforce minimum sample size: no model persisted, route falls back to signature-only
            return None

        feature_matrix: list[list[float]] = []
        for req, raw_body in corpus:
            vec = extract_features(req, raw_body)
            feature_matrix.append(vec.to_array())

        X = np.array(feature_matrix, dtype=np.float64)

        # Train Isolation Forest
        model: IsolationForest = IsolationForest(
            contamination=self.contamination,  # type: ignore[reportArgumentType]
            random_state=self.random_state,
            n_estimators=100,
        )
        model.fit(X)  # type: ignore[reportUnknownMemberType]

        out_path = Path(output_dir)
        out_path.mkdir(parents=True, exist_ok=True)

        model_filename = f"{route_id}_{version}.joblib"
        meta_filename = f"{route_id}_{version}.meta.json"

        model_file = out_path / model_filename
        joblib.dump(model, model_file)  # type: ignore[reportUnknownMemberType]

        metadata = ModelMetadata(
            model_id=route_id,
            route_id=route_id,
            version=version,
            trained_at=datetime.now(UTC),
            sample_count=sample_count,
            feature_names=FEATURE_NAMES,
            threshold=0.75,
        )

        meta_file = out_path / meta_filename
        meta_file.write_text(metadata.model_dump_json(indent=2), encoding="utf-8")

        return metadata
