# syntax=docker/dockerfile:1
#
# Multi-stage build for waffy-core / waffy-api. This image is an
# evaluation/dev convenience (see docker-compose.yml + docs/DEPLOYMENT.md)
# for quickly trying waffy without a manual systemd setup -- it is not a
# claimed replacement for the documented production systemd path
# (deploy/systemd/waffy-core.service), and parity with that path has not
# been independently verified.
#
# Runs as a non-root user, mirroring deploy/systemd/waffy-core.service's own
# `User=waffy` privilege-separation discipline -- containerizing waffy is
# not a reason to give up that hardening.

FROM python:3.12-slim AS builder

RUN pip install --no-cache-dir uv==0.12.7

WORKDIR /build
COPY pyproject.toml uv.lock README.md ./
COPY waffy ./waffy

# The `ml` extra (scikit-learn/numpy) is included despite the Docker eval
# entrypoints (waffy/runtime/serve_core.py / serve_api.py) never
# instantiating AnomalyScorer -- found during this step that it's not
# actually optional at import time: waffy/http/pipeline.py unconditionally
# imports waffy.detection.anomaly.scorer, which imports
# waffy.detection.anomaly.baseline, which imports `joblib` at module scope.
# Without this extra, `python -m waffy.runtime.serve_core` fails with
# ModuleNotFoundError before it can even start (confirmed by trying it).
# Documented as a found packaging gap in docs/PROGRESS.md rather than
# silently worked around by, e.g., lazy-importing joblib inside
# waffy/detection/anomaly/baseline.py -- that's a different module's
# concern, out of scope for this Docker-focused step.
RUN uv sync --frozen --no-editable --no-dev --extra ml


FROM python:3.12-slim AS runtime

# Fixed UID/GID shared by every service defined in docker-compose.yml --
# required so the waffy-core and waffy-api containers, which share the IPC
# Unix domain socket via a mounted volume, see each other as the same
# owning user (the socket is created with 0o600 permissions, owner-only).
RUN groupadd --gid 10001 waffy \
    && useradd --uid 10001 --gid waffy --create-home --shell /usr/sbin/nologin waffy

WORKDIR /app
COPY --from=builder /build/.venv /app/.venv
COPY waffy ./waffy
COPY config ./config

ENV PATH="/app/.venv/bin:${PATH}" \
    PYTHONUNBUFFERED=1

RUN mkdir -p /run/waffy && chown waffy:waffy /run/waffy

USER waffy

EXPOSE 8080 9090

# docker-compose.yml overrides this for the waffy-api service.
CMD ["python", "-m", "waffy.runtime.serve_core"]
