"""Run frozen local development/holdout evaluations and export all errors and metrics."""

import argparse
import json
from pathlib import Path

from app.services.detection_benchmark import DetectionBenchmark


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, default=Path("runtime/detection-benchmark"))
    parser.add_argument("--require-targets", action="store_true",
                        help="Exit 1 when holdout quality targets fail; do not use test success as quality success")
    args = parser.parse_args()
    benchmark = DetectionBenchmark()
    args.output_dir.mkdir(parents=True, exist_ok=True)
    reports = {}
    for split in ("development", "holdout"):
        report = benchmark.evaluate(split)
        reports[split] = report
        path = args.output_dir / f"{split}.json"
        path.write_bytes((json.dumps(report, ensure_ascii=False, indent=2) + "\n").encode("utf-8"))
        print(json.dumps({"split": split, "cases": report["case_count"], "families": report["family_count"],
                          "unique_patterns": report["unique_signal_pattern_count"],
                          "confusion": report["confusion"], "metrics": report["metrics"],
                          "rule_coverage_rate": report["rule_coverage_rate"],
                          "gate_passed": report["gate_passed"], "report": str(path)}, ensure_ascii=False))
    return 1 if args.require_targets and not reports["holdout"]["gate_passed"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
