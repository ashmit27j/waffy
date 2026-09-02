#!/usr/bin/env python3
"""Attack-lab measurement runner.

Measures, per paranoia level:
  - true-positive rate per attack category (synthetic corpus, corpus.py)
  - false-positive rate against the synthetic benign-traffic corpus

This is a measurement tool, not a tuning tool — it never modifies
waffy/detection/signatures/, waffy/detection/positive/, or
config/rules/seed_rules.toml, and it never assumes or hardcodes a 0%
false-positive rate. Run with `--report` for a human-readable table or
`--json` for machine-readable output (used by tests/security/).
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

from corpus import ATTACK_CORPUS, benign_raw_bodies, load_benign_corpus  # noqa: E402

from waffy.core.enums import ParanoiaLevel  # noqa: E402
from waffy.detection.signatures import SignatureEngine, load_all_rules_from_dir  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[2]
RULES_DIR = REPO_ROOT / "config" / "rules"


def measure_level(paranoia_level: ParanoiaLevel) -> dict[str, Any]:
    """Run the full attack + benign corpus through the signature engine at one paranoia level."""
    signatures = load_all_rules_from_dir(RULES_DIR)
    engine = SignatureEngine(signatures, paranoia_level=paranoia_level)

    category_results: dict[str, dict[str, Any]] = {}
    for category, cases in ATTACK_CORPUS.items():
        detected = 0
        case_details: list[dict[str, Any]] = []
        for case in cases:
            request = case.to_request()
            matches = engine.match(request, case.raw_body)
            hit = any(m.category == category for m in matches)
            if hit:
                detected += 1
            case_details.append({"name": case.name, "detected": hit})
        total = len(cases)
        rate = (detected / total * 100.0) if total else 0.0
        category_results[category.value] = {
            "detected": detected,
            "total": total,
            "true_positive_rate_pct": round(rate, 2),
            "cases": case_details,
        }

    benign_records = load_benign_corpus()
    benign_bodies = benign_raw_bodies()
    false_positives = 0
    fp_details: list[dict[str, Any]] = []
    for idx, record in enumerate(benign_records):
        body = benign_bodies[idx] if idx < len(benign_bodies) else b""
        matches = engine.match(record, body)
        if matches:
            false_positives += 1
            fp_details.append(
                {
                    "path": record.path,
                    "matched_categories": sorted({m.category.value for m in matches}),
                }
            )
    total_benign = len(benign_records)
    fp_rate = (false_positives / total_benign * 100.0) if total_benign else 0.0

    return {
        "paranoia_level": int(paranoia_level),
        "categories": category_results,
        "benign": {
            "false_positives": false_positives,
            "total": total_benign,
            "false_positive_rate_pct": round(fp_rate, 2),
            "false_positive_details": fp_details,
        },
    }


def measure_all_levels() -> list[dict[str, Any]]:
    """Run the measurement at every defined paranoia level (PL1-PL4)."""
    return [measure_level(pl) for pl in ParanoiaLevel]


def print_report(results: list[dict[str, Any]]) -> None:
    """Print a human-readable table of the measurement results."""
    for level_result in results:
        pl = level_result["paranoia_level"]
        print(f"\n=== Paranoia Level {pl} ===")
        print(f"{'Category':<24} {'TP Rate':>10} {'Detected/Total':>16}")
        print("-" * 52)
        for category, data in level_result["categories"].items():
            print(
                f"{category:<24} "
                f"{data['true_positive_rate_pct']:>9.2f}% "
                f"{data['detected']:>7}/{data['total']:<8}"
            )
        benign = level_result["benign"]
        print("-" * 52)
        print(
            f"{'benign_false_positive':<24} "
            f"{benign['false_positive_rate_pct']:>9.2f}% "
            f"{benign['false_positives']:>7}/{benign['total']:<8}"
        )
        if benign["false_positive_details"]:
            print("  False positives on:")
            for fp in benign["false_positive_details"]:
                cats = ", ".join(fp["matched_categories"])
                print(f"    - {fp['path']} (matched: {cats})")


def main() -> int:
    parser = argparse.ArgumentParser(description="waffy attack-lab corpus measurement runner")
    parser.add_argument(
        "--report", action="store_true", help="Print a human-readable report (default view)"
    )
    parser.add_argument(
        "--json", action="store_true", help="Print machine-readable JSON instead of a table"
    )
    args = parser.parse_args()

    results = measure_all_levels()

    if args.json:
        print(json.dumps(results, indent=2))
    else:
        print_report(results)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
