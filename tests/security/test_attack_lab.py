"""Pytest wrapper around scripts/attack-lab/run_corpus.py.

Invokes the runner as a subprocess (rather than importing it) because
scripts/attack-lab/ is a plain script directory, not an importable package —
its hyphenated name is intentional, matching the task-file convention. This
keeps the runner's own type-checking scope out of `pyright --strict`'s
`waffy`/`tests` include list while still letting the real, measured output
be asserted on here.
"""

import json
import subprocess
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
RUNNER = REPO_ROOT / "scripts" / "attack-lab" / "run_corpus.py"

# Categories with only a PL2+ seed signature (open_redirect is PL2) are
# expected to score 0% true-positive at PL1 — that's correct gating
# behavior, not a detection gap.
PL2_ONLY_CATEGORIES = {"open_redirect"}


def _run_corpus_json() -> list[dict[str, Any]]:
    result = subprocess.run(
        [sys.executable, str(RUNNER), "--json"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=True,
    )
    return json.loads(result.stdout)


def test_runner_executes_and_produces_all_paranoia_levels() -> None:
    results = _run_corpus_json()
    levels = [r["paranoia_level"] for r in results]
    assert levels == [1, 2, 3, 4]


def test_pl1_detects_every_category_with_a_pl1_signature() -> None:
    results = _run_corpus_json()
    pl1 = next(r for r in results if r["paranoia_level"] == 1)
    for category, data in pl1["categories"].items():
        if category in PL2_ONLY_CATEGORIES:
            assert data["detected"] == 0, (
                f"{category} unexpectedly detected at PL1 (should be PL2-gated)"
            )
        else:
            assert data["detected"] > 0, (
                f"{category} had zero true positives at PL1: {data}"
            )


def test_pl2_gates_in_open_redirect() -> None:
    results = _run_corpus_json()
    pl2 = next(r for r in results if r["paranoia_level"] == 2)
    assert pl2["categories"]["open_redirect"]["detected"] > 0


def test_benign_corpus_false_positive_rate_is_measured_not_assumed() -> None:
    """Report the actual measured FP rate at every paranoia level.

    Currently measured as 0% at all levels against the shared benign
    fixture — asserted here as a regression guard on that *measured* value,
    not as a blind assumption (see docs/PROGRESS.md Phase 9 entry for the
    full per-run numbers).
    """
    results = _run_corpus_json()
    for level_result in results:
        benign = level_result["benign"]
        assert benign["total"] > 0
        rate = benign["false_positive_rate_pct"]
        assert 0.0 <= rate <= 100.0
        print(
            f"PL{level_result['paranoia_level']} benign FP rate: "
            f"{rate}% ({benign['false_positives']}/{benign['total']})"
        )
        assert benign["false_positives"] == 0, (
            f"Measured {benign['false_positives']} false positive(s) at "
            f"PL{level_result['paranoia_level']}: {benign['false_positive_details']}"
        )


def test_ssti_freemarker_runtime_gap_is_known_and_stable() -> None:
    """Documents a real, measured signature gap rather than hiding it.

    WAFFY-SSTI-001's `${...}` alternative requires `Runtime`/`exec`/a digit
    expression immediately before the closing `}`; `${Runtime.getRuntime()}`
    ends in `()}` so it does not match. This is not a bug in the corpus —
    it's an honest true-positive-rate finding. If a future signature change
    closes this gap, this test should be updated to expect 100%, not deleted.
    """
    results = _run_corpus_json()
    pl1 = next(r for r in results if r["paranoia_level"] == 1)
    ssti = pl1["categories"]["ssti"]
    assert ssti["total"] == 3
    assert ssti["detected"] == 2
    undetected = [c["name"] for c in ssti["cases"] if not c["detected"]]
    assert undetected == ["freemarker_runtime"]
