"""Free deterministic replay of frozen LLM outputs through existing hybrid routing.

No credential loading, provider requests or latency simulation. Never a fresh
hybrid/API performance measurement or independent acceptance evaluation.
"""

import argparse
import asyncio
import hashlib
import json
import statistics
from pathlib import Path

from app.analyzers.hybrid import HybridAnalyzer
from app.analyzers.rule_based import RuleBasedAnalyzer
from app.config import Settings
from app.grounded_prompting import GROUNDED_INSTRUCTIONS, grounded_input
from app.models import SecurityAssessment
from scripts.compare_llm_grounded import compare_rows
from scripts.evaluate_llm_development import development_cases, write_json
from scripts.evaluate_llm_grounded import metrics, prediction
from scripts.retry_incomplete_evaluation import load_source


def replay_settings(*, review_all=False):
    return Settings(
        _env_file=None,
        app_environment="test",
        auth_mode="disabled",
        analyzer_mode="hybrid",
        openai_prompt_mode="grounded",
        hybrid_review_all=review_all,
        hybrid_confidence_threshold=Settings.model_fields["hybrid_confidence_threshold"].default,
        hybrid_llm_timeout_seconds=Settings.model_fields["hybrid_llm_timeout_seconds"].default,
    )


class FrozenLLM:
    def __init__(self, rows):
        self.calls = []
        self.rows = {row["id"]: row for row in rows}
        self.assessments = {}
        for row in rows:
            if row.get("error") is not None:
                if row["error"] != "StructuredResponseFailure" or row.get("assessment") is not None:
                    raise ValueError("source_failure_has_assessment")
                continue
            assessment = SecurityAssessment.model_validate(row["assessment"])
            if prediction(assessment) is not row["prediction"]:
                raise ValueError("source_assessment_prediction_mismatch")
            self.assessments[row["id"]] = assessment

    async def analyze(self, event):
        self.calls.append(event.event_id)
        if self.rows[event.event_id].get("error") is not None:
            raise RuntimeError("frozen_source_provider_failure")
        return self.assessments[event.event_id]


async def replay_arm(rows, cases, *, mode):
    if mode not in {"rule", "hybrid_default", "hybrid_review_all"}:
        raise ValueError("replay_mode")
    replay = FrozenLLM(rows)
    config = replay_settings(review_all=mode == "hybrid_review_all")
    analyzer = RuleBasedAnalyzer() if mode == "rule" else HybridAnalyzer(config, llm=replay)
    if mode != "rule":
        assert analyzer._llm is replay  # Never instantiate a live provider.
    result = []
    for source in rows:
        event = cases[source["id"]].event.model_copy(
            update={"event_id": source["id"], "ground_truth": None}
        )
        before = len(replay.calls)
        assessed = await analyzer.analyze(event)
        used = len(replay.calls) != before
        result.append(
            {
                "id": source["id"],
                "domain": source["domain"],
                "family_id": source["family_id"],
                "truth": source["truth"],
                "prediction": prediction(assessed),
                "error": None,
                "reused_LLM_output": used,
                "source_LLM_prediction": source["prediction"],
                "source_LLM_error": source.get("error"),
                "source_failure_rule_fallback": used and source.get("error") is not None,
                "requires_human_review": assessed.requires_human_review,
                "assessment": assessed.model_dump(mode="json"),
            }
        )
    return result


def load_published(path=None):
    root = Path(__file__).resolve().parents[1]
    path = (
        Path(path)
        if path is not None
        else root / "docs/infrastructure-results/llm-development360-20261117.json"
    )
    published = json.loads(path.read_bytes())
    plan, report, rows = published["plan"], published["report"], published["rows"]
    cases_path = root / "app/data/benchmark/cases.jsonl"
    if hashlib.sha256(cases_path.read_bytes()).hexdigest() != plan["cases_sha256"]:
        raise ValueError("published_population_changed")
    cases = {
        hashlib.sha256(case.case_id.encode()).hexdigest(): case
        for case in development_cases(cases_path)
    }
    if len(rows) != 360 or {row["id"] for row in rows} != set(cases):
        raise ValueError("published_cohort_changed")
    for row in rows:
        case = cases[row["id"]]
        if row["truth"] is not case.threat or (row["domain"], row["family_id"]) != (
            case.domain,
            case.family_id,
        ):
            raise ValueError("published_case_labels_changed")
    compare_rows(rows, rows)
    if (
        report.get("completed") is not True
        or report["attempts"] != 360
        or metrics(rows) != report["metrics"]
    ):
        raise ValueError("published_metrics_changed")
    return plan, report, rows, cases


def run(source, directory):
    source, directory = Path(source) if source is not None else None, Path(directory)
    if directory.exists() or (
        source is not None and directory.resolve().is_relative_to(source.resolve())
    ):
        raise ValueError("output_exists_or_overlaps_source")
    root = Path(__file__).resolve().parents[1]
    public_path = root / "docs/infrastructure-results/llm-development360-20261117.json"
    if source is None:
        plan, report, rows, cases = load_published(public_path)
        messages = None
        source_files = {"published_results.json": public_path}
    else:
        plan, report, rows, cases, messages, _ = load_source(source)
        source_files = {
            name: source / name
            for name in (
                "plan.json",
                "report.json",
                "private/inputs.jsonl",
                "private/predictions.jsonl",
            )
        }
    if rows != json.loads(public_path.read_bytes())["rows"]:
        raise ValueError("source_differs_from_published_original")
    FrozenLLM(rows)  # Validate all assessments before creating an experiment.
    rebuilt = []
    for row in rows:
        event = cases[row["id"]].event.model_copy(
            update={"event_id": row["id"], "ground_truth": None}
        )
        expected = [{"role": "system", "content": GROUNDED_INSTRUCTIONS}, *grounded_input(event)]
        if messages is not None and messages[row["id"]] != expected:
            raise ValueError("frozen_source_input_drift")
        rebuilt.append({"id": row["id"], "messages": expected})
    encoded_inputs = b"".join(
        (json.dumps(row, ensure_ascii=False) + "\n").encode() for row in rebuilt
    )
    if hashlib.sha256(encoded_inputs).hexdigest() != plan["inputs_sha256"]:
        raise ValueError("regenerated_frozen_input_hash_mismatch")
    directory.mkdir(parents=True)
    names = (
        "scripts/replay_hybrid_development.py",
        "app/analyzers/hybrid.py",
        "app/analyzers/rule_based.py",
        "app/config.py",
        "app/grounded_prompting.py",
        "scripts/retry_incomplete_evaluation.py",
        "scripts/compare_llm_grounded.py",
        "scripts/evaluate_llm_grounded.py",
        "docs/infrastructure-results/llm-development360-20261117.json",
    )
    protocol = {
        "schema": "frozen-hybrid-routing-replay-1",
        "source_kind": "committed_published_results" if source is None else "original_private_run",
        "regenerated_inputs_sha256": hashlib.sha256(encoded_inputs).hexdigest(),
        "source_file_sha256": {
            name: hashlib.sha256(path.read_bytes()).hexdigest()
            for name, path in source_files.items()
        },
        "source_pins": {},
        "cases_sha256": plan["cases_sha256"],
        "source_model": plan["model"],
        "cases": 360,
        "variants": ["rule", "hybrid_default", "hybrid_review_all"],
        "confidence_threshold": replay_settings().hybrid_confidence_threshold,
        "configured_hybrid_timeout_seconds": replay_settings().hybrid_llm_timeout_seconds,
        "live_timeouts_or_cancellation_replayed": False,
        "source_format_failure": "existing hybrid rule fallback; preserve source error separately",
        "source_UNKNOWN": "pass the actual structured UNKNOWN through the existing merge; never force a label",
        "development_gate": "no lost TP, no new FP, non-decreasing F1, at least one correction vs standalone frozen LLM",
        "runtime_adoption": False,
        "fresh_provider_requests": 0,
        "independent_acceptance": False,
    }
    for name in names:
        data = (root / name).read_bytes()
        protocol["source_pins"][name] = hashlib.sha256(data).hexdigest()
        target = directory / "source-snapshot" / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
    write_json(directory / "protocol.json", protocol)
    outputs = {
        mode: asyncio.run(replay_arm(rows, cases, mode=mode)) for mode in protocol["variants"]
    }
    comparisons = {mode: compare_rows(rows, part) for mode, part in outputs.items()}
    durations = [row["latency_seconds"] for row in rows]
    result = {
        "schema": protocol["schema"],
        "protocol_sha256": hashlib.sha256((directory / "protocol.json").read_bytes()).hexdigest(),
        "source_metrics": report["metrics"],
        "metrics": {mode: metrics(part) for mode, part in outputs.items()},
        "comparisons": comparisons,
        "development_gate_passed": {
            mode: comparison["no_lost_detections"]
            and comparison["no_new_false_positives"]
            and comparison["candidate"]["F1"] >= comparison["reference"]["F1"]
            and bool(comparison["recovered_TP_ids"] or comparison["corrected_FP_ids"])
            for mode, comparison in comparisons.items()
        },
        "reused_model_outputs": {
            mode: sum(row["reused_LLM_output"] for row in part) for mode, part in outputs.items()
        },
        "source_failure_fallbacks": {
            mode: sum(row["source_failure_rule_fallback"] for row in part)
            for mode, part in outputs.items()
        },
        "source_model_UNKNOWN_or_error": report["metrics"]["unknown_or_error"],
        "observed_source_SDK_latency_seconds": {
            "cases": len(durations),
            "median": statistics.median(durations),
            "maximum": max(durations),
            "above_default_hybrid_timeout": sum(
                d > protocol["configured_hybrid_timeout_seconds"] for d in durations
            ),
            "not_a_hybrid_timeout_test": True,
        },
        "fresh_provider_requests": 0,
        "runtime_adoption": False,
        "historical_metrics_replaced": False,
        "independent_acceptance": False,
        "rows": outputs,
    }
    for name, expected in protocol["source_file_sha256"].items():
        assert hashlib.sha256(source_files[name].read_bytes()).hexdigest() == expected
    write_json(directory / "report.json", result)
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--source",
        type=Path,
        help="Optional original private run; omit to use committed public results",
    )
    parser.add_argument("--directory", type=Path, required=True)
    args = parser.parse_args()
    result = run(args.source, args.directory)
    print(json.dumps({k: v for k, v in result.items() if k not in {"rows", "comparisons"}}))
